/* SPDX-License-Identifier: GPL-2.0 */
/*
 * common.h — Utilidades compartidas por las pruebas de mmap-guard.
 *
 * Cada prueba recibe la ruta de un archivo de prueba y la expectativa ("deny" o "allow"):
 *   - deny  : el guard está cargado y la operación debe fallar con EPERM.
 *   - allow : el guard NO está cargado (línea base) y la operación debe funcionar.
 * Código de salida: 0 = PASS, 1 = FAIL, 2 = error de entorno.
 *
 * Las pruebas solo actúan sobre archivos temporales creados por tests/run_all.sh.
 */
#ifndef MG_TEST_COMMON_H
#define MG_TEST_COMMON_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures;

static inline int parse_expect(int argc, char **argv, const char **path)
{
    if (argc != 3 || (strcmp(argv[2], "deny") && strcmp(argv[2], "allow"))) {
        fprintf(stderr, "Uso: %s <archivo> <deny|allow>\n", argv[0]);
        exit(2);
    }
    *path = argv[1];
    return strcmp(argv[2], "deny") == 0;
}

/* Verifica una operación que la política debe bloquear cuando expect_deny = 1.
 * ok = la operación tuvo éxito; err = errno si falló. */
static inline void check_guarded(const char *what, int ok, int err, int expect_deny)
{
    int pass;

    if (expect_deny)
        pass = !ok && err == EPERM;
    else
        pass = ok;
    printf("  [%s] %-45s -> %s%s%s\n", pass ? "PASS" : "FAIL", what,
           ok ? "permitido" : "denegado", ok ? "" : " errno=", ok ? "" : strerror(err));
    if (!pass)
        g_failures++;
}

/* Verifica una operación de control que SIEMPRE debe funcionar (el guard no debe
 * romper usos legítimos). */
static inline void check_control(const char *what, int ok, int err)
{
    printf("  [%s] %-45s -> %s%s%s\n", ok ? "PASS" : "FAIL", what,
           ok ? "permitido" : "denegado", ok ? "" : " errno=", ok ? "" : strerror(err));
    if (!ok)
        g_failures++;
}

/* Hash FNV-1a de 64 bits del contenido completo del archivo leído con read(2), es decir,
 * desde el page cache, que es lo que vería cualquier otro proceso. Devuelve 0 si falla. */
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
static inline uint64_t file_hash(const char *path)
{
    unsigned char buf[4096];
    uint64_t h = 1469598103934665603ULL;
    ssize_t n;
    int fd = open(path, O_RDONLY);

    if (fd < 0)
        return 0;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t i;

        for (i = 0; i < n; i++) {
            h ^= buf[i];
            h *= 1099511628211ULL;
        }
    }
    close(fd);
    return n < 0 ? 0 : h;
}

static inline int finish(const char *name)
{
    printf("%s: %s\n", name, g_failures ? "FAIL" : "PASS");
    return g_failures ? 1 : 0;
}

#endif /* MG_TEST_COMMON_H */
