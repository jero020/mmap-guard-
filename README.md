# mmap-guard

Defensa en la **capa de kernel** para archivos mapeados con `mmap()`. Usa hooks **eBPF-LSM**
(`mmap_file`, `file_mprotect`) para bloquear escrituras compartidas, mapeos ejecutables y
escaladas de permisos vía `mprotect()` sobre archivos protegidos, con auditoría por ring
buffer y un módulo de kernel (LKM) que mide page faults y ofrece un modo de bloqueo de
respaldo para kernels sin BPF-LSM.

> Parcial 25 %, Sistemas Operativos, EAFIT 2026-2:
> *Seguridad de Archivos mediante Intervención en la Capa del Kernel y mmap*.

| Documento | Contenido |
|---|---|
| [`docs/preguntas-diagnosticas.md`](docs/preguntas-diagnosticas.md) | Parte I: las 10 preguntas |
| [`docs/ia-bitacora.md`](docs/ia-bitacora.md) | Parte II: flujo con IA, prompts, alucinaciones, validación |
| [`docs/arquitectura.md`](docs/arquitectura.md) | Parte II: diagrama y decisiones de diseño |
| [`docs/tradeoffs.md`](docs/tradeoffs.md) | Parte II: matriz rendimiento vs. seguridad |

## Descripción

Con `mmap()`, después del primer page fault, los accesos los resuelve la MMU **sin entrar al
kernel**, así que un mapeo `MAP_SHARED + PROT_WRITE` es un canal de escritura al archivo que
no pasa por `write()`. mmap-guard controla los dos momentos en que el kernel otorga permisos
sobre esa memoria:

| Ataque | Hook | Resultado |
|---|---|---|
| `mmap(PROT_WRITE, MAP_SHARED)` sobre archivo protegido | `lsm/mmap_file` | `EPERM` |
| `mmap(PROT_EXEC)` sobre archivo `noexec` | `lsm/mmap_file` | `EPERM` |
| `mmap(PROT_READ)` y luego `mprotect(+PROT_WRITE)` (VMA compartido) | `lsm/file_mprotect` | `EPERM` |
| `mprotect(+PROT_EXEC)` sobre VMA de archivo protegido | `lsm/file_mprotect` | `EPERM` |
| Lectura (compartida o privada) y escritura privada (COW) | — | permitido: no modifica el archivo |

Cada decisión sobre un archivo protegido genera un evento (pid, uid, comm, inode, prot,
flags, decisión, motivo) que `mmap_guardd` imprime en tiempo real.

## Arquitectura

```
             Ring 3                               Ring 0
 ┌──────────────────────────┐   mapas BPF   ┌──────────────────────────────────────┐
 │ mmap_guardd (loader)     │──────────────▶│ protected_inodes (dev,ino)→política  │
 │  · protected.conf→inodes │               │ uid_whitelist · guard_config · stats │
 │  · imprime auditoría     │◀── ringbuf ───│ lsm/mmap_file      lsm/file_mprotect │
 └──────────────────────────┘               └──────────────────────────────────────┘
 ┌──────────────────────────┐   /proc       ┌──────────────────────────────────────┐
 │ tests/ · bench.sh        │◀──────────────│ pf_monitor.ko: kprobe handle_mm_fault│
 └──────────────────────────┘               │ (+ kretprobes security_* si enforce) │
                                            └──────────────────────────────────────┘
```

Detalle y diagrama de flujo en [`docs/arquitectura.md`](docs/arquitectura.md).

```
bpf/        mmap_guard.bpf.c (hooks LSM), mmap_guard.h (tipos compartidos)
loader/     mmap_guardd.c (libbpf skeleton, config, ring buffer)
lkm/        pf_monitor.c + Kbuild
tests/      pruebas en C, run_all.sh, bench.sh, bench_mmap.c
config/     protected.conf
scripts/    check_env.sh
docs/       informe (Partes I y II)
```

## Requisitos

- Linux **5.8+** (ring buffer BPF; BPF-LSM existe desde 5.7). Probado con headers 6.8.
- `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_KPROBES=y`, `CONFIG_KRETPROBES=y`.
- **`bpf` en `/sys/kernel/security/lsm`**. Si no aparece, agrega `bpf` al parámetro de
  arranque, por ejemplo en `/etc/default/grub`:
  `GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,bpf"`, luego
  `sudo update-grub && sudo reboot`.
  En **OrbStack** o WSL no se controla el arranque: usa el **modo respaldo** del LKM.
- Paquetes (Ubuntu): `sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev make gcc linux-tools-$(uname -r) linux-headers-$(uname -r)`

Diagnóstico automático:

```bash
./scripts/check_env.sh
```

## Compilación

```bash
make            # bpf + loader + lkm + tests, todo con -Werror
make bpf        # build/mmap_guard.bpf.o y build/mmap_guard.skel.h
make loader     # build/mmap_guardd
make lkm        # lkm/pf_monitor.ko
make tests      # build/tests/*
make clean
```

`bpf/vmlinux.h` se genera automáticamente desde `/sys/kernel/btf/vmlinux` y no se versiona.

## Uso

### Modo principal (eBPF-LSM)

```bash
sudo ./build/mmap_guardd -c config/protected.conf      # bloqueo
sudo ./build/mmap_guardd -a -A                          # solo auditoría, incluye permitidos
sudo ./build/mmap_guardd -i                             # identificar solo por inode (btrfs/overlayfs)
```

Formato de `config/protected.conf`:

```
protect   /ruta/archivo     # bloquea escritura compartida y mprotect(+W/+X)
noexec    /ruta/binario     # bloquea PROT_EXEC y mprotect(+X)
allow_uid 1000              # audita pero no bloquea a este UID
```

Ejemplo de salida:

```
16:58:01.204 mmap     DENY       shared_write pid=4211   uid=1000  comm=test_mmap_share ino=37 prot=rw- flags=0x1
16:58:01.205 mprotect DENY       mprotect_+w  pid=4212   uid=1000  comm=test_mprotect_e ino=37 prot=rw- flags=0xfb
```

### Medición y modo respaldo (LKM)

```bash
sudo insmod lkm/pf_monitor.ko ino=$(stat -c %i archivo)             # solo medición
sudo insmod lkm/pf_monitor.ko ino=$(stat -c %i archivo) enforce=1   # bloqueo con kretprobes
cat /proc/mmap_guard_stats
echo reset | sudo tee /proc/mmap_guard_stats
sudo rmmod pf_monitor
```

## Pruebas

```bash
sudo ./tests/run_all.sh              # elige bpf o lkm según el kernel
sudo ./tests/run_all.sh --mode lkm   # fuerza el modo respaldo
```

Cada prueba se ejecuta dos veces: **sin guard** (el ataque debe funcionar, lo que demuestra el
riesgo) y **con guard** (debe fallar con `EPERM` mientras los usos legítimos siguen funcionando).

| Prueba | Qué demuestra |
|---|---|
| `test_mmap_shared_write` | bloqueo de `MAP_SHARED`/`MAP_SHARED_VALIDATE` + `PROT_WRITE` |
| `test_mprotect_escalation` | bloqueo de la evasión R → W / R → X con `mprotect` |
| `test_mmap_exec` | bloqueo de `PROT_EXEC` sobre archivos `noexec` |
| `test_rdonly_private` | `O_RDONLY + MAP_PRIVATE + PROT_WRITE` se permite (COW) y el archivo no cambia (hash) |
| `test_concurrency` | estrés con COW + `MADV_DONTNEED` + intentos compartidos: sin oops, denegación consistente, integridad |

Solo se usan archivos temporales en `/dev/shm/mmap-guard-demo`. No se incluyen exploits de CVEs reales.

## Resultados

```bash
sudo ./tests/bench.sh 100000     # guarda results/bench_<fecha>.txt
```

| Configuración | `mmap+munmap` (ns/op) | fault de lectura (ns/página) | page-faults (`perf stat`) |
|---|---|---|---|
| base | _pendiente_ | _pendiente_ | _pendiente_ |
| BPF-LSM | _pendiente_ | _pendiente_ | _pendiente_ |
| LKM pf_monitor | _pendiente_ | _pendiente_ | _pendiente_ |

Lo esperado: BPF-LSM agrega un costo pequeño y constante por `mmap()`/`mprotect()` (dos
búsquedas hash) y **cero por acceso**; el kprobe en `handle_mm_fault` encarece todos los page
faults del sistema, por eso se usa solo para medir.

### ¿Por qué en kernel y no en espacio de usuario?

- Un wrapper con `LD_PRELOAD` se evade con una syscall directa, un binario estático o `io_uring`.
- Después del primer fault ningún código de usuario ve los accesos, y el kernel solo los ve
  en los faults. El único punto que no se puede evadir es la creación o el cambio de permisos
  del VMA, dentro del kernel.
- El hook LSM recibe el `struct file` ya resuelto (no la ruta ni el fd), así que no hay TOCTOU.

## Limitaciones y trabajo futuro

- **No inspecciona contenido**: elimina el canal de escritura compartida en lugar de filtrar lo
  que se escribe. Inspeccionar exigiría actuar en `->writepages` o forzar faults por escritura.
- **Mapeos previos a la carga**: los VMAs creados antes de cargar el guard conservan sus
  permisos. Mitigación: cargarlo temprano en el arranque (servicio systemd).
- **Otros canales hacia el page cache** quedan fuera del alcance de estos hooks: `write()`
  directo (se controla con permisos POSIX/LSM `file_permission`), `/proc/<pid>/mem`,
  `process_vm_writev`, `splice`. Se podrían cubrir con los hooks `file_permission` y `ptrace_access_check`.
- **Root**: un usuario con `CAP_SYS_ADMIN`/`CAP_BPF` puede descargar el programa. Mitigación:
  *lockdown*, firmar programas BPF o fijarlos (`bpf_link` *pinned*) con un LSM que proteja `bpffs`.
- **Comodín de dispositivo (`-i`)**: en btrfs/overlayfs dos archivos de sistemas de archivos
  distintos con el mismo número de inode recibirían la misma política.
- **Modo respaldo**: los kretprobes dependen de que los wrappers `security_*` no se compilen
  inline y tienen un `maxactive` finito.
- **Hardware/hipervisor**: la confidencialidad del texto plano en RAM requiere cifrado de
  memoria (AMD SEV/SME, Intel TME/TDX) y aislamiento de DMA con IOMMU; un hipervisor puede
  imponer permisos de página de segundo nivel (EPT) que el kernel invitado no puede cambiar.

## Licencia

GPL-2.0 (requerida por los helpers BPF-LSM y por el LKM).
