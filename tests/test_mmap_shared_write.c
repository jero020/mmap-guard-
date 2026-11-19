// SPDX-License-Identifier: GPL-2.0
/*
 * test_mmap_shared_write.c — Intenta modificar un archivo protegido vía MAP_SHARED.
 *
 * Con MAP_SHARED + PROT_WRITE, una escritura en memoria marca la página del page cache
 * como sucia y el writeback la lleva a disco: no pasa por write(2), así que permisos o
 * auditoría basados en write() no la ven. El hook lsm/mmap_file debe denegarla.
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

    printf("test_mmap_shared_write (%s, espera %s)\n", path, argv[2]);
    fd = open(path, O_RDWR);
    if (fd < 0) {
        perror("open O_RDWR");
        return 2;
    }

    /* Ataque: mapeo compartido con escritura. */
    p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check_guarded("mmap(PROT_WRITE, MAP_SHARED)", p != MAP_FAILED, errno, expect_deny);
    if (p != MAP_FAILED)
        munmap(p, len);

    /* Variante: MAP_SHARED_VALIDATE (Linux 4.15+) también es compartido. */
    p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED_VALIDATE, fd, 0);
    check_guarded("mmap(PROT_WRITE, MAP_SHARED_VALIDATE)", p != MAP_FAILED, errno,
                  expect_deny);
    if (p != MAP_FAILED)
        munmap(p, len);

    /* Control: lectura compartida debe seguir funcionando. */
    p = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    check_control("control mmap(PROT_READ, MAP_SHARED)", p != MAP_FAILED, errno);
    if (p != MAP_FAILED)
        munmap(p, len);

    /* Control: escritura privada (COW) no toca el archivo y se permite. */
    p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    check_control("control mmap(PROT_WRITE, MAP_PRIVATE)", p != MAP_FAILED, errno);
    if (p != MAP_FAILED)
        munmap(p, len);

    close(fd);
    return finish("test_mmap_shared_write");
}
