// SPDX-License-Identifier: GPL-2.0
/*
 * test_rdonly_private.c — ¿Se pueden evadir los permisos POSIX con mmap?
 *
 * Escenario (pregunta 8 del parcial): un proceso abre un archivo con O_RDONLY y lo mapea
 * con PROT_WRITE | MAP_PRIVATE. El kernel lo PERMITE, porque MAP_PRIVATE no exige
 * FMODE_WRITE: en do_mmap() solo MAP_SHARED con PROT_WRITE requiere VM_MAYWRITE.
 * La primera escritura provoca un fault que, por Copy-On-Write, copia la página del page
 * cache a una página anónima privada del proceso (do_wp_page / wp_page_copy). El archivo
 * nunca cambia.
 *
 * La prueba demuestra las tres cosas:
 *   1. O_RDONLY + MAP_SHARED + PROT_WRITE   -> bloqueado. Sin guard: EACCES (chequeo
 *      FMODE_WRITE en do_mmap). Con guard: EPERM, porque vm_mmap_pgoff() llama a
 *      security_mmap_file() ANTES de do_mmap(), así que el LSM decide primero.
 *   2. O_RDONLY + MAP_PRIVATE + PROT_WRITE  -> permitido, y la escritura es visible
 *      solo dentro del proceso.
 *   3. El contenido en disco/page cache (hash con read(2)) es idéntico antes y después.
 *
 * Uso: test_rdonly_private <archivo>
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include "common.h"

int main(int argc, char **argv)
{
    size_t len = (size_t)sysconf(_SC_PAGESIZE);
    uint64_t before, after;
    unsigned char *p;
    void *q;
    int fd, ok;

    if (argc != 2) {
        fprintf(stderr, "Uso: %s <archivo>\n", argv[0]);
        return 2;
    }
    printf("test_rdonly_private (%s)\n", argv[1]);

    before = file_hash(argv[1]);
    fd = open(argv[1], O_RDONLY);
    if (fd < 0 || before == 0) {
        perror("open/hash");
        return 2;
    }

    /* 1. Escritura compartida sobre fd de solo lectura: el kernel debe dar EACCES. */
    q = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ok = (q == MAP_FAILED && (errno == EACCES || errno == EPERM));
    printf("  [%s] %-45s -> %s%s\n", ok ? "PASS" : "FAIL", "O_RDONLY + MAP_SHARED + PROT_WRITE",
           q == MAP_FAILED ? strerror(errno) : "permitido (¡inesperado!)",
           q != MAP_FAILED ? "" : errno == EPERM ? " (lo negó el LSM)" : " (lo negó do_mmap)");
    if (!ok)
        g_failures++;
    if (q != MAP_FAILED)
        munmap(q, len);

    /* 2. Escritura privada: permitida; dispara COW en el primer acceso. */
    p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    check_control("O_RDONLY + MAP_PRIVATE + PROT_WRITE", p != MAP_FAILED, errno);
    if (p != MAP_FAILED) {
        unsigned char orig = p[0];

        memset(p, 'X', len);                 /* fault de escritura -> COW */
        ok = (p[0] == 'X');
        printf("  [%s] %-45s -> p[0] 0x%02x -> 0x%02x\n", ok ? "PASS" : "FAIL",
               "la escritura es visible en el proceso", orig, p[0]);
        if (!ok)
            g_failures++;
        msync(p, len, MS_SYNC);              /* en MAP_PRIVATE no escribe nada al archivo */
        munmap(p, len);
    }
    close(fd);

    /* 3. Integridad: el archivo no cambió. */
    after = file_hash(argv[1]);
    ok = (before == after);
    printf("  [%s] %-45s -> %016llx %s %016llx\n", ok ? "PASS" : "FAIL",
           "hash del archivo antes == después", (unsigned long long)before,
           ok ? "==" : "!=", (unsigned long long)after);
    if (!ok)
        g_failures++;

    return finish("test_rdonly_private");
}
