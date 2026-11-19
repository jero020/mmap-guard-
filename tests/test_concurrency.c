// SPDX-License-Identifier: GPL-2.0
/*
 * test_concurrency.c — Estrés concurrente benigno sobre un archivo protegido.
 *
 * Reproduce la FORMA de carga que explotaba Dirty COW (CVE-2016-5195): hilos que escriben
 * en un mapeo privado (COW) mientras otros descartan las páginas con
 * madvise(MADV_DONTNEED), más hilos que intentan mapeos compartidos con escritura.
 * NO incluye el vector del exploit (escritura por /proc/self/mem): el objetivo es
 * verificar que, bajo concurrencia, (a) el kernel no produce oops, (b) el guard deniega
 * de forma consistente y (c) el archivo conserva su integridad (hash).
 *
 * Uso: test_concurrency <archivo> <deny|allow> [hilos] [iteraciones]
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include "common.h"

static const char *g_path;
static size_t g_len;
static long g_iters = 2000;
static atomic_long shared_ok, shared_eperm, shared_other, cow_writes, dontneed;

/* Hilo tipo A: COW. Escribe en un mapeo privado y descarta la página. */
static void *cow_worker(void *arg)
{
    int fd = open(g_path, O_RDONLY);
    long i;

    (void)arg;
    if (fd < 0)
        return NULL;
    for (i = 0; i < g_iters; i++) {
        unsigned char *p = mmap(NULL, g_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

        if (p == MAP_FAILED)
            continue;
        p[i % g_len] ^= 0xff;                 /* fault de escritura -> página COW */
        atomic_fetch_add(&cow_writes, 1);
        madvise(p, g_len, MADV_DONTNEED);     /* descarta la copia privada */
        atomic_fetch_add(&dontneed, 1);
        (void)p[i % g_len];                   /* vuelve a leer: debe ver el original */
        munmap(p, g_len);
    }
    close(fd);
    return NULL;
}

/* Hilo tipo B: intenta mapear compartido con escritura y lo libera SIN escribir, para
 * que la prueba de integridad sea válida también sin el guard cargado. */
static void *shared_worker(void *arg)
{
    int fd = open(g_path, O_RDWR);
    long i;

    (void)arg;
    if (fd < 0)
        return NULL;
    for (i = 0; i < g_iters; i++) {
        void *p = mmap(NULL, g_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

        if (p != MAP_FAILED) {
            atomic_fetch_add(&shared_ok, 1);
            munmap(p, g_len);
        } else if (errno == EPERM) {
            atomic_fetch_add(&shared_eperm, 1);
        } else {
            atomic_fetch_add(&shared_other, 1);
        }
    }
    close(fd);
    return NULL;
}

int main(int argc, char **argv)
{
    int expect_deny, nthreads = 8, i, ok;
    uint64_t before, after;
    pthread_t *th;

    if (argc < 3) {
        fprintf(stderr, "Uso: %s <archivo> <deny|allow> [hilos] [iteraciones]\n", argv[0]);
        return 2;
    }
    {
        char *a[3] = { argv[0], argv[1], argv[2] };
        expect_deny = parse_expect(3, a, &g_path);
    }
    if (argc > 3)
        nthreads = atoi(argv[3]);
    if (argc > 4)
        g_iters = atol(argv[4]);
    if (nthreads < 2)
        nthreads = 2;
    g_len = (size_t)sysconf(_SC_PAGESIZE);

    printf("test_concurrency (%s, espera %s, %d hilos x %ld iteraciones)\n",
           g_path, argv[2], nthreads, g_iters);
    before = file_hash(g_path);
    if (before == 0) {
        perror("hash");
        return 2;
    }

    th = calloc((size_t)nthreads, sizeof(*th));
    if (!th)
        return 2;
    for (i = 0; i < nthreads; i++)
        pthread_create(&th[i], NULL, (i % 2) ? shared_worker : cow_worker, NULL);
    for (i = 0; i < nthreads; i++)
        pthread_join(th[i], NULL);
    free(th);

    after = file_hash(g_path);
    printf("  escrituras COW=%ld  MADV_DONTNEED=%ld\n", (long)cow_writes, (long)dontneed);
    printf("  mmap compartido: ok=%ld  EPERM=%ld  otros=%ld\n",
           (long)shared_ok, (long)shared_eperm, (long)shared_other);

    ok = (before == after);
    printf("  [%s] %-45s -> %016llx %s %016llx\n", ok ? "PASS" : "FAIL",
           "integridad del archivo (hash)", (unsigned long long)before, ok ? "==" : "!=",
           (unsigned long long)after);
    if (!ok)
        g_failures++;

    /* Consistencia del guard: con deny, NINGÚN mapeo compartido debe haber pasado. */
    ok = expect_deny ? (shared_ok == 0 && shared_eperm > 0) : (shared_eperm == 0);
    printf("  [%s] %-45s\n", ok ? "PASS" : "FAIL",
           expect_deny ? "todas las escrituras compartidas denegadas"
                       : "sin denegaciones (línea base)");
    if (!ok)
        g_failures++;

    return finish("test_concurrency");
}
