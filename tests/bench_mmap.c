// SPDX-License-Identifier: GPL-2.0
/*
 * bench_mmap.c — Microbenchmark del costo que agrega mmap-guard.
 *
 * Mide dos cosas, en nanosegundos por operación (CLOCK_MONOTONIC):
 *   1. mmap()+munmap() de solo lectura: cada llamada pasa por security_mmap_file(),
 *      es decir, por el hook BPF (o el kretprobe del modo respaldo).
 *   2. Page faults de lectura: se mapean N páginas y se toca cada una. Con pf_monitor
 *      cargado, cada fault ejecuta además el kprobe de handle_mm_fault.
 *      Antes de cada ronda se usa MADV_DONTNEED para que todas las páginas vuelvan a fallar.
 *
 * Uso: bench_mmap <archivo> [iteraciones]   (el archivo debe tener >= 1 MiB)
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    long iters = argc > 2 ? atol(argv[2]) : 100000;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t npages, len;
    volatile unsigned char sink = 0;
    uint64_t t0, t1, faults = 0;
    struct stat st;
    long i;
    int fd, rounds = 50, r;

    if (argc < 2) {
        fprintf(stderr, "Uso: %s <archivo> [iteraciones]\n", argv[0]);
        return 2;
    }
    fd = open(argv[1], O_RDONLY);
    if (fd < 0 || fstat(fd, &st) < 0) {
        perror(argv[1]);
        return 2;
    }
    npages = (size_t)st.st_size / page;
    if (npages > 256)
        npages = 256;
    if (npages == 0) {
        fprintf(stderr, "archivo demasiado pequeño\n");
        return 2;
    }
    len = npages * page;

    /* 1. Costo del hook en mmap(). */
    t0 = now_ns();
    for (i = 0; i < iters; i++) {
        void *p = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);

        if (p == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        munmap(p, page);
    }
    t1 = now_ns();
    printf("mmap_munmap_ns_por_op %.1f\n", (double)(t1 - t0) / (double)iters);

    /* 2. Costo por page fault de lectura. */
    {
        unsigned char *p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
        uint64_t total = 0;

        if (p == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        for (r = 0; r < rounds; r++) {
            size_t k;

            madvise(p, len, MADV_DONTNEED);   /* quita los PTE: el próximo acceso falla */
            t0 = now_ns();
            for (k = 0; k < npages; k++)
                sink ^= p[k * page];
            total += now_ns() - t0;
            faults += npages;
        }
        munmap(p, len);
        printf("fault_lectura_ns_por_pagina %.1f\n", (double)total / (double)faults);
    }
    (void)sink;
    close(fd);
    return 0;
}
