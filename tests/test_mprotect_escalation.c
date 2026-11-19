// SPDX-License-Identifier: GPL-2.0
/*
 * test_mprotect_escalation.c — Evasión "mapear de solo lectura y luego subir permisos".
 *
 * Un atacante que sabe que mmap(PROT_WRITE) se bloquea puede pedir PROT_READ (permitido)
 * y después llamar mprotect(PROT_READ|PROT_WRITE) o mprotect(PROT_EXEC). El archivo se
 * abre O_RDWR para que el chequeo VM_MAYWRITE del kernel NO lo detenga antes: así se
 * prueba exactamente el hook lsm/file_mprotect.
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
    int fd, r;

    printf("test_mprotect_escalation (%s, espera %s)\n", path, argv[2]);
    fd = open(path, O_RDWR);
    if (fd < 0) {
        perror("open O_RDWR");
        return 2;
    }

    p = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    check_control("paso 1: mmap(PROT_READ, MAP_SHARED)", p != MAP_FAILED, errno);
    if (p == MAP_FAILED) {
        close(fd);
        return finish("test_mprotect_escalation");
    }

    r = mprotect(p, len, PROT_READ | PROT_WRITE);
    check_guarded("paso 2: mprotect(+PROT_WRITE) en VMA compartido", r == 0, errno,
                  expect_deny);

    r = mprotect(p, len, PROT_READ | PROT_EXEC);
    check_guarded("paso 3: mprotect(+PROT_EXEC)", r == 0, errno, expect_deny);

    /* Control: bajar permisos (a PROT_NONE) siempre se permite. */
    r = mprotect(p, len, PROT_NONE);
    check_control("control mprotect(PROT_NONE)", r == 0, errno);

    munmap(p, len);
    close(fd);
    return finish("test_mprotect_escalation");
}
