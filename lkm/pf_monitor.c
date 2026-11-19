// SPDX-License-Identifier: GPL-2.0
/*
 * pf_monitor.c — Módulo de kernel (LKM) de medición para mmap-guard.
 *
 * Coloca un kprobe en handle_mm_fault() (mm/memory.c), la función por la que pasa TODO
 * page fault de usuario después de que el handler de la arquitectura (exc_page_fault en
 * x86) encuentra el VMA. Cuenta los fallos sobre VMAs respaldados por los inodes
 * indicados en el parámetro `ino`, separando lectura, escritura, COW y faults en VMAs
 * compartidos. Los resultados se leen en /proc/mmap_guard_stats.
 *
 * Esto ilustra un límite clave de mmap(): el kernel solo "ve" el PRIMER acceso a cada
 * página (el fault). Una vez instalado el PTE, la MMU resuelve los accesos siguientes
 * en hardware y ningún hook del kernel se ejecuta.
 *
 * MODO RESPALDO (enforce=1): si el kernel no tiene "bpf" en la lista de LSM activos
 * (p. ej. el kernel de OrbStack), los hooks eBPF-LSM no se pueden adjuntar. En ese caso
 * el módulo registra kretprobes sobre security_mmap_file() y security_file_mprotect() y,
 * cuando la operación viola la política, reemplaza el valor de retorno por -EPERM.
 * Es menos limpio que un LSM (depende de que el símbolo no se inline y de la convención
 * de registros), pero no requiere recompilar el kernel ni cambiar parámetros de arranque.
 *
 * Restricciones de diseño:
 *   - NO modifica sys_call_table ni desactiva el bit WP de CR0.
 *   - No usa kallsyms_lookup_name (no exportado desde Linux 5.7): los kprobes resuelven
 *     el símbolo por nombre de forma soportada.
 *
 * Uso: sudo insmod pf_monitor.ko ino=123456,789012 [enforce=1]
 *      cat /proc/mmap_guard_stats
 *      echo reset | sudo tee /proc/mmap_guard_stats
 */
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROC_NAME  "mmap_guard_stats"
#define MAX_INODES 16

static unsigned long ino[MAX_INODES];
static int n_ino;
module_param_array(ino, ulong, &n_ino, 0444);
MODULE_PARM_DESC(ino, "Números de inode a monitorear (separados por coma, máx. 16)");

static bool enforce;
module_param(enforce, bool, 0444);
MODULE_PARM_DESC(enforce, "1 = modo respaldo: bloquear con kretprobes sobre security_*");

/* Contadores globales. atomic64 porque el kprobe corre en paralelo en todas las CPUs. */
static atomic64_t faults_total;     /* faults sobre inodes monitoreados */
static atomic64_t faults_write;     /* FAULT_FLAG_WRITE                  */
static atomic64_t faults_read;
static atomic64_t faults_shared;    /* VMA con VM_SHARED                  */
static atomic64_t faults_cow;       /* escritura en VMA privado => COW    */
static atomic64_t faults_seen;      /* todos los faults (denominador)     */
static atomic64_t denied_mmap;      /* modo respaldo: mmap denegados      */
static atomic64_t denied_mprotect;  /* modo respaldo: mprotect denegados  */

static bool inode_monitored(unsigned long i)
{
    int k;

    for (k = 0; k < n_ino; k++)
        if (ino[k] == i)
            return true;
    return false;
}

/*
 * vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
 *                            unsigned int flags, struct pt_regs *regs);
 * (firma desde Linux 5.10; verificada en include/linux/mm.h de 6.8)
 * regs_get_kernel_argument() abstrae la convención de llamada (rdi/rsi/rdx en x86_64,
 * x0/x1/x2 en arm64).
 */
static int pf_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct vm_area_struct *vma;
    unsigned int flags;
    struct file *file;

    (void)p;
    atomic64_inc(&faults_seen);

    vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 0);
    flags = (unsigned int)regs_get_kernel_argument(regs, 2);
    if (!vma)
        return 0;
    file = vma->vm_file;                 /* NULL para VMAs anónimos */
    if (!file || !inode_monitored(file_inode(file)->i_ino))
        return 0;

    atomic64_inc(&faults_total);
    if (vma->vm_flags & VM_SHARED)
        atomic64_inc(&faults_shared);
    if (flags & FAULT_FLAG_WRITE) {
        atomic64_inc(&faults_write);
        if (!(vma->vm_flags & VM_SHARED))
            atomic64_inc(&faults_cow);   /* escritura en mapeo privado: Copy-On-Write */
    } else {
        atomic64_inc(&faults_read);
    }
    return 0;                            /* 0 = continuar con la función original */
}

static struct kprobe pf_kp = {
    .symbol_name = "handle_mm_fault",
    .pre_handler = pf_pre_handler,
};

/* --------------------------- Modo respaldo -------------------------------------- */

/* Datos por instancia de kretprobe: se calculan a la entrada y se usan al retorno. */
struct guard_data {
    bool deny;
};

/* int security_mmap_file(struct file *file, unsigned long prot, unsigned long flags);
 * (include/linux/security.h, 6.8). OJO: el wrapper NO recibe reqprot, a diferencia del
 * hook LSM mmap_file. */
static int mmap_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct guard_data *d = (struct guard_data *)ri->data;
    struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
    unsigned long prot = regs_get_kernel_argument(regs, 1);
    unsigned long type = regs_get_kernel_argument(regs, 2) & MAP_TYPE;

    d->deny = false;
    if (!file || !inode_monitored(file_inode(file)->i_ino))
        return 0;
    if ((prot & PROT_WRITE) && (type == MAP_SHARED || type == MAP_SHARED_VALIDATE))
        d->deny = true;
    else if (prot & PROT_EXEC)
        d->deny = true;
    return 0;                            /* 0 = ejecutar también el handler de retorno */
}

/* int security_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
 *                            unsigned long prot); */
static int mprotect_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct guard_data *d = (struct guard_data *)ri->data;
    struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 0);
    unsigned long prot = regs_get_kernel_argument(regs, 2);
    unsigned long vmf;

    d->deny = false;
    if (!vma || !vma->vm_file || !inode_monitored(file_inode(vma->vm_file)->i_ino))
        return 0;
    vmf = vma->vm_flags;
    if ((prot & PROT_WRITE) && !(vmf & VM_WRITE) && (vmf & VM_SHARED))
        d->deny = true;                  /* escalada R -> W en mapeo compartido */
    else if ((prot & PROT_EXEC) && !(vmf & VM_EXEC))
        d->deny = true;                  /* escalada a ejecutable */
    return 0;
}

/* Al retorno: si la política se viola y ningún LSM ya negó, forzar -EPERM. */
static int guard_ret(struct kretprobe_instance *ri, struct pt_regs *regs, atomic64_t *ctr)
{
    struct guard_data *d = (struct guard_data *)ri->data;

    if (d->deny && regs_return_value(regs) == 0) {
        regs_set_return_value(regs, (unsigned long)-EPERM);
        atomic64_inc(ctr);
    }
    return 0;
}

static int mmap_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return guard_ret(ri, regs, &denied_mmap);
}

static int mprotect_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return guard_ret(ri, regs, &denied_mprotect);
}

static struct kretprobe mmap_krp = {
    .kp.symbol_name = "security_mmap_file",
    .entry_handler  = mmap_entry,
    .handler        = mmap_ret,
    .data_size      = sizeof(struct guard_data),
    .maxactive      = 64,                /* llamadas concurrentes rastreables */
};

static struct kretprobe mprotect_krp = {
    .kp.symbol_name = "security_file_mprotect",
    .entry_handler  = mprotect_entry,
    .handler        = mprotect_ret,
    .data_size      = sizeof(struct guard_data),
    .maxactive      = 64,
};

/* ------------------------------- /proc ------------------------------------------- */

static int stats_show(struct seq_file *m, void *v)
{
    int k;

    (void)v;
    seq_puts(m, "inodes_monitoreados:");
    for (k = 0; k < n_ino; k++)
        seq_printf(m, " %lu", ino[k]);
    seq_putc(m, '\n');
    seq_printf(m, "faults_totales_sistema: %lld\n", atomic64_read(&faults_seen));
    seq_printf(m, "faults_inodes:          %lld\n", atomic64_read(&faults_total));
    seq_printf(m, "  lectura:              %lld\n", atomic64_read(&faults_read));
    seq_printf(m, "  escritura:            %lld\n", atomic64_read(&faults_write));
    seq_printf(m, "  en_vma_compartido:    %lld\n", atomic64_read(&faults_shared));
    seq_printf(m, "  cow_privado:          %lld\n", atomic64_read(&faults_cow));
    seq_printf(m, "modo_respaldo:          %s\n", enforce ? "activo" : "inactivo");
    seq_printf(m, "  mmap_denegados:       %lld\n", atomic64_read(&denied_mmap));
    seq_printf(m, "  mprotect_denegados:   %lld\n", atomic64_read(&denied_mprotect));
    return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, stats_show, NULL);
}

/* Escribir "reset" pone los contadores en cero. */
static ssize_t stats_write(struct file *file, const char __user *buf, size_t len,
                           loff_t *off)
{
    char kbuf[8] = {};

    (void)file;
    (void)off;
    if (copy_from_user(kbuf, buf, min(len, sizeof(kbuf) - 1)))
        return -EFAULT;
    if (strncmp(kbuf, "reset", 5) != 0)
        return -EINVAL;
    atomic64_set(&faults_seen, 0);
    atomic64_set(&faults_total, 0);
    atomic64_set(&faults_read, 0);
    atomic64_set(&faults_write, 0);
    atomic64_set(&faults_shared, 0);
    atomic64_set(&faults_cow, 0);
    atomic64_set(&denied_mmap, 0);
    atomic64_set(&denied_mprotect, 0);
    return (ssize_t)len;
}

/* struct proc_ops reemplazó a file_operations para /proc en Linux 5.6. */
static const struct proc_ops stats_ops = {
    .proc_open    = stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = stats_write,
};

static struct proc_dir_entry *proc_entry;

static int __init pf_monitor_init(void)
{
    int ret;

    proc_entry = proc_create(PROC_NAME, 0644, NULL, &stats_ops);
    if (!proc_entry)
        return -ENOMEM;

    ret = register_kprobe(&pf_kp);
    if (ret < 0) {
        pr_err("pf_monitor: register_kprobe(handle_mm_fault) falló: %d\n", ret);
        proc_remove(proc_entry);
        return ret;
    }
    if (enforce) {
        ret = register_kretprobe(&mmap_krp);
        if (ret == 0) {
            ret = register_kretprobe(&mprotect_krp);
            if (ret < 0)
                unregister_kretprobe(&mmap_krp);
        }
        if (ret < 0) {
            pr_err("pf_monitor: register_kretprobe falló: %d\n", ret);
            unregister_kprobe(&pf_kp);
            proc_remove(proc_entry);
            return ret;
        }
    }
    pr_info("pf_monitor: kprobe en %s, %d inode(s), modo respaldo %s\n",
            pf_kp.symbol_name, n_ino, enforce ? "ACTIVO" : "inactivo");
    return 0;
}

static void __exit pf_monitor_exit(void)
{
    /* unregister_kprobe() espera a que terminen los handlers en curso (RCU), así que
     * después de esta llamada es seguro liberar el resto. */
    if (enforce) {
        unregister_kretprobe(&mprotect_krp);
        unregister_kretprobe(&mmap_krp);
        if (mmap_krp.nmissed || mprotect_krp.nmissed)
            pr_warn("pf_monitor: instancias perdidas (maxactive): mmap=%d mprotect=%d\n",
                    mmap_krp.nmissed, mprotect_krp.nmissed);
    }
    unregister_kprobe(&pf_kp);
    proc_remove(proc_entry);
    pr_info("pf_monitor: descargado\n");
}

module_init(pf_monitor_init);
module_exit(pf_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jero020");
MODULE_DESCRIPTION("mmap-guard: medición de page faults sobre archivos protegidos");
