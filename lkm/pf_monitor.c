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
 * Restricciones de diseño:
 *   - NO modifica sys_call_table ni desactiva el bit WP de CR0.
 *   - No usa kallsyms_lookup_name (no exportado desde Linux 5.7): los kprobes resuelven
 *     el símbolo por nombre de forma soportada.
 *
 * Uso: sudo insmod pf_monitor.ko ino=123456,789012
 *      cat /proc/mmap_guard_stats
 *      echo reset | sudo tee /proc/mmap_guard_stats
 */
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
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

/* Contadores globales. atomic64 porque el kprobe corre en paralelo en todas las CPUs. */
static atomic64_t faults_total;     /* faults sobre inodes monitoreados */
static atomic64_t faults_write;     /* FAULT_FLAG_WRITE                  */
static atomic64_t faults_read;
static atomic64_t faults_shared;    /* VMA con VM_SHARED                  */
static atomic64_t faults_cow;       /* escritura en VMA privado => COW    */
static atomic64_t faults_seen;      /* todos los faults (denominador)     */

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
    pr_info("pf_monitor: kprobe en %s (%px), %d inode(s)\n",
            pf_kp.symbol_name, pf_kp.addr, n_ino);
    return 0;
}

static void __exit pf_monitor_exit(void)
{
    /* unregister_kprobe() espera a que terminen los handlers en curso (RCU), así que
     * después de esta llamada es seguro liberar el resto. */
    unregister_kprobe(&pf_kp);
    proc_remove(proc_entry);
    pr_info("pf_monitor: descargado\n");
}

module_init(pf_monitor_init);
module_exit(pf_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jero020");
MODULE_DESCRIPTION("mmap-guard: medición de page faults sobre archivos protegidos");
