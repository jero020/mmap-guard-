// SPDX-License-Identifier: GPL-2.0
/*
 * mmap_guard.bpf.c — Programas eBPF-LSM de mmap-guard.
 *
 * Los programas BPF_PROG_TYPE_LSM se adjuntan a los hooks del framework LSM (security/)
 * mediante trampolinas BPF. Se ejecutan en Ring 0, en el contexto del proceso que hace la
 * llamada, ANTES de que el kernel cree el VMA (mmap) o cambie sus permisos (mprotect).
 * Devolver un valor negativo (p. ej. -EPERM) hace fallar la syscall.
 *
 * Requisitos del kernel:
 *   - CONFIG_BPF_LSM=y                (BPF-LSM existe desde Linux 5.7)
 *   - "bpf" en /sys/kernel/security/lsm (parámetro de arranque lsm=...,bpf)
 *   - CONFIG_DEBUG_INFO_BTF=y          (CO-RE: BPF_CORE_READ reubica offsets en carga)
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mmap_guard.h"

char LICENSE[] SEC("license") = "GPL";   /* los helpers LSM exigen licencia compatible GPL */

#define EPERM 1

/* ---------------------------------------------------------------------------------- */
/* Mapas                                                                               */
/* ---------------------------------------------------------------------------------- */

/* (dev, ino) -> bits MG_POL_*. Lo llena el loader desde config/protected.conf. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct mg_inode_key);
    __type(value, __u32);
} protected_inodes SEC(".maps");

/* UIDs en lista blanca: se auditan pero no se bloquean. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} uid_whitelist SEC(".maps");

/* Configuración global (un solo elemento). Se llama guard_config porque "config"
 * choca con un typedef de vmlinux.h. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mg_config);
} guard_config SEC(".maps");

/* Contadores por decisión, por CPU (sin contención entre núcleos). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MG_DECISION_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* Canal de auditoría hacia espacio de usuario (BPF ring buffer, Linux 5.8+). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* ---------------------------------------------------------------------------------- */
/* Utilidades                                                                          */
/* ---------------------------------------------------------------------------------- */

/* Obtiene (s_dev, i_ino) del inode que respalda un struct file. */
static __always_inline int file_to_key(struct file *file, struct mg_inode_key *key)
{
    struct inode *inode;

    if (!file)
        return -1;                       /* mmap anónimo: no hay archivo */
    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return -1;
    key->dev = BPF_CORE_READ(inode, i_sb, s_dev);
    key->ino = BPF_CORE_READ(inode, i_ino);
    return 0;
}

static __always_inline struct mg_config *get_config(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&guard_config, &zero);
}

static __always_inline void count(__u32 decision)
{
    __u64 *c = bpf_map_lookup_elem(&stats, &decision);
    if (c)
        (*c)++;                          /* per-CPU: no requiere atómicos */
}

static __always_inline int uid_whitelisted(__u32 uid)
{
    return bpf_map_lookup_elem(&uid_whitelist, &uid) != NULL;
}

/* Envía un evento de auditoría. Si el ring buffer está lleno el evento se pierde,
 * pero la decisión de seguridad NO depende de que el envío funcione. */
static __always_inline void emit(__u32 hook, const struct mg_inode_key *key,
                                 __u64 prot, __u64 flags, __u32 decision, __u32 reason)
{
    struct mg_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    e->ts_ns    = bpf_ktime_get_ns();
    e->dev      = key->dev;
    e->ino      = key->ino;
    e->prot     = prot;
    e->flags    = flags;
    e->pid      = pid_tgid >> 32;
    e->tid      = (__u32)pid_tgid;
    e->uid      = (__u32)bpf_get_current_uid_gid();
    e->hook     = hook;
    e->decision = decision;
    e->reason   = reason;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

/* Decide a partir del motivo encontrado y la configuración. Devuelve el código del hook. */
static __always_inline int decide(__u32 hook, const struct mg_inode_key *key,
                                  __u64 prot, __u64 flags, __u32 reason)
{
    struct mg_config *cfg = get_config();
    __u32 enforce = cfg ? cfg->enforce : 1;        /* por defecto: bloquear */
    __u32 audit_allow = cfg ? cfg->audit_allow : 0;
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    __u32 decision;

    if (reason == MG_R_NONE) {
        count(MG_ALLOW);
        if (audit_allow)
            emit(hook, key, prot, flags, MG_ALLOW, MG_R_NONE);
        return 0;
    }

    if (uid_whitelisted(uid))
        decision = MG_ALLOW_WHITELIST;
    else if (enforce)
        decision = MG_DENY;
    else
        decision = MG_WOULD_DENY;

    count(decision);
    emit(hook, key, prot, flags, decision, reason);
    return decision == MG_DENY ? -EPERM : 0;
}

/* ---------------------------------------------------------------------------------- */
/* Hook 1: mmap_file                                                                   */
/* ---------------------------------------------------------------------------------- */
/*
 * Firma (include/linux/lsm_hook_defs.h, verificada en 6.8):
 *   LSM_HOOK(int, 0, mmap_file, struct file *file, unsigned long reqprot,
 *            unsigned long prot, unsigned long flags)
 * Lo invoca security_mmap_file() desde vm_mmap_pgoff() y ksys_mmap_pgoff(), es decir
 * antes de do_mmap(): todavía no existe el vm_area_struct ni hay PTEs.
 *   reqprot = protección pedida por el usuario
 *   prot    = protección efectiva (incluye PROT_EXEC si READ_IMPLIES_EXEC está activo)
 *   flags   = flags MAP_* de mmap(2)
 * El último argumento de BPF_PROG es el valor devuelto por el LSM anterior en la cadena.
 */
SEC("lsm/mmap_file")
int BPF_PROG(mg_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    struct mg_inode_key key = {};
    __u32 *policy;
    __u32 reason = MG_R_NONE;
    __u32 type = flags & MG_MAP_TYPE;

    (void)reqprot;
    if (ret != 0)
        return ret;                      /* otro LSM ya denegó: respetar su decisión */
    if (file_to_key(file, &key) < 0)
        return 0;

    policy = bpf_map_lookup_elem(&protected_inodes, &key);
    if (!policy)
        return 0;                        /* camino rápido: archivo no protegido */

    if ((*policy & MG_POL_NO_SHARED_WRITE) && (prot & MG_PROT_WRITE) &&
        (type == MG_MAP_SHARED || type == MG_MAP_SHARED_VALIDATE))
        reason = MG_R_SHARED_WRITE;      /* escribiría directamente en el page cache */
    else if ((*policy & MG_POL_NO_EXEC) && (prot & MG_PROT_EXEC))
        reason = MG_R_EXEC;              /* mapeo ejecutable: posible inyección de código */

    return decide(MG_HOOK_MMAP_FILE, &key, prot, flags, reason);
}

/* ---------------------------------------------------------------------------------- */
/* Hook 2: file_mprotect                                                               */
/* ---------------------------------------------------------------------------------- */
/*
 * Firma (include/linux/lsm_hook_defs.h, verificada en 6.8):
 *   LSM_HOOK(int, 0, file_mprotect, struct vm_area_struct *vma,
 *            unsigned long reqprot, unsigned long prot)
 * Lo invoca security_file_mprotect() desde do_mprotect_pkey() (mm/mprotect.c), por cada
 * VMA afectado, DESPUÉS del chequeo VM_MAY* del kernel (que da -EACCES si el archivo se
 * abrió O_RDONLY) y ANTES de mprotect_fixup(), que es quien reescribe vm_flags y los PTE.
 *
 * Cierra la evasión "mapear PROT_READ (permitido) y luego subir a PROT_WRITE/PROT_EXEC":
 * sin este hook, mmap_file solo vería la protección inicial.
 *
 * Desde Linux 6.3 vm_flags es una unión (vm_flags / __vm_flags); BPF_CORE_READ resuelve
 * el miembro "vm_flags" igual en ambas versiones.
 */
SEC("lsm/file_mprotect")
int BPF_PROG(mg_file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot, int ret)
{
    struct mg_inode_key key = {};
    struct file *file;
    __u32 *policy;
    __u32 reason = MG_R_NONE;
    unsigned long vmf;

    (void)reqprot;
    if (ret != 0)
        return ret;

    file = BPF_CORE_READ(vma, vm_file);
    if (file_to_key(file, &key) < 0)
        return 0;                        /* VMA anónimo (heap, stack, MAP_ANONYMOUS) */

    policy = bpf_map_lookup_elem(&protected_inodes, &key);
    if (!policy)
        return 0;

    vmf = BPF_CORE_READ(vma, vm_flags);

    /* +W sobre un VMA compartido: las escrituras irían al page cache y luego a disco.
     * +W sobre un VMA privado se permite: es Copy-On-Write y nunca llega al archivo. */
    if ((*policy & MG_POL_NO_MPROTECT_UP) && (prot & MG_PROT_WRITE) &&
        !(vmf & MG_VM_WRITE) && (vmf & MG_VM_SHARED))
        reason = MG_R_MPROTECT_WRITE;
    /* +X sobre cualquier VMA de un archivo protegido. */
    else if ((*policy & (MG_POL_NO_EXEC | MG_POL_NO_MPROTECT_UP)) &&
             (prot & MG_PROT_EXEC) && !(vmf & MG_VM_EXEC))
        reason = MG_R_MPROTECT_EXEC;

    return decide(MG_HOOK_FILE_MPROTECT, &key, prot, vmf, reason);
}
