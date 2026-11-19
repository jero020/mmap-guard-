// SPDX-License-Identifier: GPL-2.0
/*
 * test_mmap_exec.c — Intenta mapear como ejecutable un archivo marcado "noexec".
 *
 * Mapear un archivo con PROT_EXEC es el paso previo a ejecutar código cargado
 * manualmente (sin execve, evitando noexec del montaje en algunos escenarios).
 * Solo se mapea: nunca se salta al contenido.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "common.h"

int main(int argc, char **argv)
{
    const char *path;
    int expect_deny = parse_expect(argc, argv, &path);
    size_t len = (size_t)sysconf(_SC_PAGESIZE);
    void *p;
    int fd;

    printf("test_mmap_exec (%s, espera %s)\n", path, argv[2]);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open O_RDONLY");
        return 2;
    }

    p = mmap(NULL, len, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    check_guarded("mmap(PROT_EXEC, MAP_PRIVATE)", p != MAP_FAILED, errno, expect_deny);
    if (p != MAP_FAILED)
        munmap(p, len);

    p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    check_control("control mmap(PROT_READ, MAP_PRIVATE)", p != MAP_FAILED, errno);
    if (p != MAP_FAILED)
        munmap(p, len);

    close(fd);
    return finish("test_mmap_exec");
}
