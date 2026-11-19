/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mmap_guard.h — Tipos compartidos entre el programa eBPF (kernel) y el loader (usuario).
 *
 * Un archivo protegido se identifica por la pareja (dispositivo, inode), NO por su ruta:
 * las rutas se pueden evadir con hardlinks, symlinks, bind mounts o /proc/self/fd/N,
 * mientras que (s_dev, i_ino) identifica unívocamente el objeto en el VFS.
 */
#ifndef MMAP_GUARD_H
#define MMAP_GUARD_H

#ifndef __VMLINUX_H__
#include <linux/types.h>   /* __u32, __u64 en espacio de usuario */
#endif

/* --- Constantes de mmap(2) ----------------------------------------------------------
 * vmlinux.h solo contiene tipos (BTF), no macros, así que las redefinimos aquí.
 * Valores de include/uapi/asm-generic/mman-common.h y mman.h (x86_64 / arm64). */
#define MG_PROT_READ        0x1
#define MG_PROT_WRITE       0x2
#define MG_PROT_EXEC        0x4
#define MG_MAP_SHARED       0x01
#define MG_MAP_PRIVATE      0x02
#define MG_MAP_SHARED_VALIDATE 0x03
#define MG_MAP_TYPE         0x0f   /* máscara del tipo de mapeo */

/* Bits de vm_area_struct->vm_flags (include/linux/mm.h). */
#define MG_VM_READ          0x00000001UL
#define MG_VM_WRITE         0x00000002UL
#define MG_VM_EXEC          0x00000004UL
#define MG_VM_SHARED        0x00000008UL

/* --- Políticas por archivo (bits de protected_inodes.value) ------------------------ */
#define MG_POL_NO_SHARED_WRITE  (1u << 0)  /* bloquea MAP_SHARED + PROT_WRITE           */
#define MG_POL_NO_EXEC          (1u << 1)  /* bloquea PROT_EXEC                         */
#define MG_POL_NO_MPROTECT_UP   (1u << 2)  /* bloquea mprotect() que agregue W o X      */

/* --- Origen del evento -------------------------------------------------------------- */
enum mg_hook {
    MG_HOOK_MMAP_FILE     = 1,
    MG_HOOK_FILE_MPROTECT = 2,
};

/* --- Decisión ----------------------------------------------------------------------- */
enum mg_decision {
    MG_ALLOW            = 0,
    MG_DENY             = 1,
    MG_ALLOW_WHITELIST  = 2,   /* habría sido denegado, pero el UID está en lista blanca */
    MG_WOULD_DENY       = 3,   /* modo auditoría (enforce=0): se habría denegado          */
    MG_DECISION_MAX     = 4,
};

/* Motivo de la denegación (o de la auditoría). */
enum mg_reason {
    MG_R_NONE           = 0,
    MG_R_SHARED_WRITE   = 1,
    MG_R_EXEC           = 2,
    MG_R_MPROTECT_WRITE = 3,
    MG_R_MPROTECT_EXEC  = 4,
};

/* Clave del mapa protected_inodes. Se rellena con ceros para que no haya padding basura. */
struct mg_inode_key {
    __u64 dev;     /* sb->s_dev (codificación interna del kernel, ver new_encode_dev) */
    __u64 ino;     /* inode->i_ino */
};

/* Configuración global (mapa array de 1 elemento). */
struct mg_config {
    __u32 enforce;      /* 0 = solo auditar, 1 = bloquear */
    __u32 audit_allow;  /* 1 = también emitir eventos de operaciones permitidas */
};

/* Evento enviado por el ring buffer al loader. */
struct mg_event {
    __u64 ts_ns;        /* bpf_ktime_get_ns() */
    __u64 dev;
    __u64 ino;
    __u64 prot;         /* protección solicitada */
    __u64 flags;        /* flags de mmap (MAP_*) o vm_flags del VMA en mprotect */
    __u32 pid;          /* tgid */
    __u32 tid;
    __u32 uid;
    __u32 hook;         /* enum mg_hook */
    __u32 decision;     /* enum mg_decision */
    __u32 reason;       /* enum mg_reason */
    char  comm[16];
};

#endif /* MMAP_GUARD_H */
