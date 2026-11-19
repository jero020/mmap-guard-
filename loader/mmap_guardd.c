// SPDX-License-Identifier: GPL-2.0
/*
 * mmap_guardd.c — Loader en espacio de usuario de mmap-guard.
 *
 * 1. Abre y carga el objeto BPF con el skeleton generado por bpftool (libbpf, CO-RE).
 *    En la carga el verificador del kernel valida el programa y libbpf reubica los
 *    offsets de struct file / inode / vm_area_struct según el BTF del kernel en ejecución.
 * 2. Lee config/protected.conf, resuelve cada ruta a (dev, inode) y llena los mapas.
 * 3. Adjunta los programas a los hooks LSM.
 * 4. Consume el ring buffer de auditoría e imprime un evento por línea hasta SIGINT/SIGTERM;
 *    al salir imprime los contadores por decisión (sumados sobre todas las CPUs).
 *
 * Uso: sudo ./build/mmap_guardd [-c conf] [-a] [-A] [-i] [-v]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "mmap_guard.h"
#include "mmap_guard.skel.h"

struct options {
    const char *conf;
    int audit_only;     /* -a: enforce = 0 */
    int audit_allow;    /* -A: emitir también eventos permitidos */
    int ino_only;       /* -i: usar comodín de dispositivo (dev = 0) */
    int verbose;        /* -v: mensajes de libbpf */
};

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
    (void)level;
    return vfprintf(stderr, fmt, args);
}

/* st_dev (formato glibc/huge_encode_dev) -> formato interno del kernel (MKDEV: MAJOR<<20). */
static __u64 to_kernel_dev(dev_t d)
{
    return ((__u64)major(d) << 20) | (__u64)minor(d);
}

static int protect_path(struct mmap_guard_bpf *skel, const char *path, __u32 policy,
                        int ino_only)
{
    struct mg_inode_key key;
    struct stat st;
    __u32 old = 0;

    if (stat(path, &st) < 0) {
        fprintf(stderr, "[conf] AVISO: no se puede proteger %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[conf] AVISO: %s no es un archivo regular, se ignora\n", path);
        return -1;
    }

    memset(&key, 0, sizeof(key));          /* sin bytes de padding indefinidos */
    key.dev = ino_only ? 0 : to_kernel_dev(st.st_dev);
    key.ino = st.st_ino;

    /* Si el mismo inode aparece en varias directivas, se combinan las políticas. */
    if (bpf_map__lookup_elem(skel->maps.protected_inodes, &key, sizeof(key),
                             &old, sizeof(old), 0) == 0)
        policy |= old;

    if (bpf_map__update_elem(skel->maps.protected_inodes, &key, sizeof(key),
                             &policy, sizeof(policy), BPF_ANY) < 0) {
        fprintf(stderr, "[conf] ERROR actualizando mapa para %s: %s\n", path, strerror(errno));
        return -1;
    }
    printf("[conf] protegido %s  dev=%u:%u ino=%llu politica=0x%x%s\n", path,
           major(st.st_dev), minor(st.st_dev), (unsigned long long)st.st_ino, policy,
           ino_only ? " (comodín dev)" : "");
    return 0;
}

static int whitelist_uid(struct mmap_guard_bpf *skel, __u32 uid)
{
    __u8 one = 1;

    if (bpf_map__update_elem(skel->maps.uid_whitelist, &uid, sizeof(uid),
                             &one, sizeof(one), BPF_ANY) < 0) {
        fprintf(stderr, "[conf] ERROR agregando uid %u: %s\n", uid, strerror(errno));
        return -1;
    }
    printf("[conf] uid %u en lista blanca\n", uid);
    return 0;
}

/* Formato: "<directiva> <argumento>" por línea; '#' inicia comentario. */
static int load_config(struct mmap_guard_bpf *skel, const struct options *o)
{
    char line[4352], cmd[32], arg[4096];
    unsigned int lineno = 0, ok = 0;
    FILE *f = fopen(o->conf, "r");

    if (!f) {
        fprintf(stderr, "No se pudo abrir %s: %s\n", o->conf, strerror(errno));
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        char *hash = strchr(line, '#');

        lineno++;
        if (hash)
            *hash = '\0';
        if (sscanf(line, "%31s %4095s", cmd, arg) != 2)
            continue;                       /* línea vacía o solo comentario */

        if (strcmp(cmd, "protect") == 0)
            ok += protect_path(skel, arg, MG_POL_NO_SHARED_WRITE | MG_POL_NO_MPROTECT_UP,
                               o->ino_only) == 0;
        else if (strcmp(cmd, "noexec") == 0)
            ok += protect_path(skel, arg, MG_POL_NO_EXEC | MG_POL_NO_MPROTECT_UP,
                               o->ino_only) == 0;
        else if (strcmp(cmd, "allow_uid") == 0)
            whitelist_uid(skel, (__u32)strtoul(arg, NULL, 10));
        else
            fprintf(stderr, "[conf] %s:%u: directiva desconocida '%s'\n", o->conf, lineno, cmd);
    }
    fclose(f);
    printf("[conf] %u archivo(s) protegido(s)\n", ok);
    return 0;
}

static const char *hook_str(__u32 h)
{
    return h == MG_HOOK_MMAP_FILE ? "mmap" : h == MG_HOOK_FILE_MPROTECT ? "mprotect" : "?";
}

static const char *decision_str(__u32 d)
{
    switch (d) {
    case MG_ALLOW:           return "ALLOW";
    case MG_DENY:            return "DENY";
    case MG_ALLOW_WHITELIST: return "ALLOW_WL";
    case MG_WOULD_DENY:      return "WOULD_DENY";
    default:                 return "?";
    }
}

static const char *reason_str(__u32 r)
{
    switch (r) {
    case MG_R_NONE:           return "-";
    case MG_R_SHARED_WRITE:   return "shared_write";
    case MG_R_EXEC:           return "exec";
    case MG_R_MPROTECT_WRITE: return "mprotect_+w";
    case MG_R_MPROTECT_EXEC:  return "mprotect_+x";
    default:                  return "?";
    }
}

static void prot_str(__u64 prot, char out[4])
{
    out[0] = (prot & MG_PROT_READ)  ? 'r' : '-';
    out[1] = (prot & MG_PROT_WRITE) ? 'w' : '-';
    out[2] = (prot & MG_PROT_EXEC)  ? 'x' : '-';
    out[3] = '\0';
}

/* Callback de ring_buffer__poll(): un evento por llamada. */
static int handle_event(void *ctx, void *data, size_t len)
{
    const struct mg_event *e = data;
    struct timespec now;
    struct tm tm;
    char prot[4], ts[16];

    (void)ctx;
    if (len < sizeof(*e))
        return 0;
    clock_gettime(CLOCK_REALTIME, &now);
    localtime_r(&now.tv_sec, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
    prot_str(e->prot, prot);

    printf("%s.%03ld %-8s %-10s %-12s pid=%-6u uid=%-5u comm=%-15.16s "
           "ino=%llu prot=%s flags=0x%llx\n",
           ts, now.tv_nsec / 1000000, hook_str(e->hook), decision_str(e->decision),
           reason_str(e->reason), e->pid, e->uid, e->comm,
           (unsigned long long)e->ino, prot, (unsigned long long)e->flags);
    fflush(stdout);
    return 0;
}

/* Suma un contador BPF_MAP_TYPE_PERCPU_ARRAY sobre todas las CPUs posibles. */
static void print_stats(struct mmap_guard_bpf *skel)
{
    int ncpu = libbpf_num_possible_cpus();
    __u64 *vals;
    __u32 d;

    if (ncpu <= 0)
        return;
    vals = calloc((size_t)ncpu, sizeof(*vals));
    if (!vals)
        return;
    printf("\n[stats] decisiones sobre archivos protegidos (incluye ALLOW solo si aplica):\n");
    for (d = 0; d < MG_DECISION_MAX; d++) {
        __u64 sum = 0;
        int c;

        if (bpf_map__lookup_elem(skel->maps.stats, &d, sizeof(d), vals,
                                 sizeof(*vals) * (size_t)ncpu, 0) < 0)
            continue;
        for (c = 0; c < ncpu; c++)
            sum += vals[c];
        printf("  %-10s %llu\n", decision_str(d), (unsigned long long)sum);
    }
    free(vals);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Uso: %s [-c conf] [-a] [-A] [-i] [-v]\n"
            "  -c conf  archivo de configuración (por defecto config/protected.conf)\n"
            "  -a       modo auditoría: registra pero NO bloquea\n"
            "  -A       registrar también las operaciones permitidas\n"
            "  -i       identificar solo por inode (necesario en btrfs/overlayfs)\n"
            "  -v       mostrar mensajes de libbpf y del verificador\n", prog);
}

int main(int argc, char **argv)
{
    struct options o = { .conf = "config/protected.conf" };
    struct mmap_guard_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct mg_config cfg;
    __u32 zero = 0;
    int opt, err = 1;

    while ((opt = getopt(argc, argv, "c:aAivh")) != -1) {
        switch (opt) {
        case 'c': o.conf = optarg; break;
        case 'a': o.audit_only = 1; break;
        case 'A': o.audit_allow = 1; break;
        case 'i': o.ino_only = 1; break;
        case 'v': o.verbose = 1; break;
        default: usage(argv[0]); return opt == 'h' ? 0 : 1;
        }
    }

    if (o.verbose)
        libbpf_set_print(libbpf_print);
    else
        libbpf_set_print(NULL);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    skel = mmap_guard_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Error cargando el programa BPF (¿root? ¿CONFIG_BPF_LSM? usa -v)\n");
        return 1;
    }

    cfg.enforce = !o.audit_only;
    cfg.audit_allow = o.audit_allow;
    if (bpf_map__update_elem(skel->maps.guard_config, &zero, sizeof(zero),
                             &cfg, sizeof(cfg), BPF_ANY) < 0) {
        fprintf(stderr, "Error escribiendo configuración: %s\n", strerror(errno));
        goto out;
    }

    if (load_config(skel, &o) < 0)
        goto out;

    if (mmap_guard_bpf__attach(skel) < 0) {
        fprintf(stderr, "Error adjuntando hooks LSM: %s\n"
                "¿Está 'bpf' en /sys/kernel/security/lsm?\n", strerror(errno));
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Error creando ring buffer: %s\n", strerror(errno));
        goto out;
    }

    printf("[mmap-guard] activo (modo %s). Ctrl+C para salir.\n",
           o.audit_only ? "AUDITORÍA" : "BLOQUEO");
    fflush(stdout);

    while (!g_stop) {
        int n = ring_buffer__poll(rb, 200 /* ms */);

        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "Error en ring_buffer__poll: %d\n", n);
            goto out;
        }
    }
    print_stats(skel);
    err = 0;

out:
    ring_buffer__free(rb);
    mmap_guard_bpf__destroy(skel);         /* desadjunta hooks y libera mapas */
    return err;
}
