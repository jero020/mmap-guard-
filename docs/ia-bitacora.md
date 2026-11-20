# Parte II — Estrategia con apoyo de IA

## 3.1 Flujo de trabajo asistido por IA

| Fase | Herramienta | Rol de la IA | Verificación humana / automática |
|---|---|---|---|
| Exploración arquitectónica | Claude (chat) | Comparar LKM vs. LSM vs. eBPF; listar hooks (`mmap_file`, `file_mprotect`) y estructuras (`vm_area_struct`, `vm_flags`) | Firmas confrontadas con `include/linux/lsm_hook_defs.h` y `security.h` de los headers 6.8 |
| Andamiaje del repositorio | GitHub Copilot (modo agente) | Generar la estructura de carpetas y archivos vacíos con TODO | Revisión del árbol con `tree` |
| Generación de código C | Claude | Programas eBPF, loader libbpf, LKM, pruebas | `make` con `-Wall -Wextra -Werror`, verificador BPF al cargar, carga real del módulo |
| Pruebas / PoC controlados | Claude | Pruebas que reproducen el riesgo (línea base) y verifican la defensa | Doble ejecución: sin guard (el ataque debe funcionar) y con guard (debe fallar con `EPERM`) |
| Documentación | Claude | Borradores de respuestas, diagramas, matriz | Contraste con el código fuente del kernel y la documentación oficial |

## 3.2 Prompts estructurados

| # | Contexto | Rol | Restricción | Resultado esperado | Resultado obtenido |
|---|---|---|---|---|---|
| 1 | Parcial de SO, kernel 5.15+/6.x, se necesita una defensa en kernel para mmap | Ingeniero senior de kernel (mm/, LSM, eBPF) | Solo helpers/hooks existentes; marcar `// VERIFICAR` si no se está seguro; sin `sys_call_table` ni CR0 | Propuesta de arquitectura eBPF-LSM + LKM y estructura del repo | Arquitectura adoptada (ver `arquitectura.md`) |
| 2 | Repositorio vacío en GitHub | Copilot como generador de andamiaje | **No implementar lógica**, solo archivos con TODO; no inventar funciones del kernel; lista cerrada de archivos | Árbol de carpetas idéntico al pedido | El repositorio estaba vacío al iniciar la implementación; la estructura final se generó con Claude siguiendo la misma lista |
| 3 | Hooks LSM de mmap en kernel 6.8 | Programador eBPF con libbpf/CO-RE | Firmas tomadas de `lsm_hook_defs.h`; identificar archivos por (dev, ino) con `BPF_CORE_READ`; respetar `ret` del LSM previo | `mmap_guard.bpf.c` que compile sin warnings y pase el verificador | Compiló; error de nombre de mapa `config` detectado (ver tabla de alucinaciones) |
| 4 | Kernel sin BPF-LSM (OrbStack) | Desarrollador de LKM | Sin `kallsyms_lookup_name`, sin CR0, liberar todo en `module_exit` | Modo respaldo con kretprobes en `security_mmap_file`/`security_file_mprotect` | Implementado en `pf_monitor.c` (`enforce=1`); en OrbStack no fue necesario porque `bpf` ya está activo |
| 5 | Validar evasión POSIX y carreras | Ingeniero de pruebas de seguridad | Solo archivos temporales propios; sin exploits de CVE reales; verificación por hash | `test_rdonly_private`, `test_concurrency` con PASS/FAIL | Implementado; se corrigió la expectativa EACCES→EPERM. Resultado final: 12/12 PASS en kernel 7.0 |
| 6 | Medición de overhead | Ingeniero de rendimiento | Usar `perf stat` y microbenchmarks; comparar base / BPF / LKM | `bench.sh` + `bench_mmap.c` | Implementado; cifras en la sección Resultados del README |

## 3.2 Alucinaciones y errores técnicos detectados

| # | Sugerencia de la IA (o error típico de LLM) | Por qué es incorrecta | Cómo se detectó | Corrección aplicada |
|---|---|---|---|---|
| 1 | Usar `kallsyms_lookup_name()` desde un LKM para encontrar `sys_call_table` | Dejó de exportarse en Linux 5.7 (`EXPORT_SYMBOL` eliminado) → el módulo no enlaza (`undefined symbol`) | Revisión contra el changelog / `nm` de `Module.symvers` | Se descartó hookear la tabla; se usan kprobes por nombre |
| 2 | Desactivar el bit WP de CR0 (`write_cr0(read_cr0() & ~0x10000)`) para escribir la tabla | Inseguro: no es atómico entre CPUs, deja todo `.rodata` escribible; desde 5.3 el *CR0 pinning* vuelve a activar WP | Conocimiento de `arch/x86/kernel/cpu/common.c` (`native_write_cr0`) | Restricción explícita en los prompts: prohibido |
| 3 | Hook LSM llamado `file_mmap` | Nombre obsoleto: desde 3.5 son `mmap_addr` y `mmap_file` | `grep mmap lsm_hook_defs.h` | Se usa `SEC("lsm/mmap_file")` |
| 4 | Suponer que `security_mmap_file()` tiene la misma firma que el hook (`file, reqprot, prot, flags`) | El wrapper es `security_mmap_file(file, prot, flags)`: no recibe `reqprot`. Leer el argumento equivocado en el kretprobe toma `flags` como `prot` | `security.h` de los headers 6.8 | Índices de argumentos corregidos en `mmap_entry()` |
| 5 | Comparar `stat().st_dev` directamente con `inode->i_sb->s_dev` | Formatos distintos: usuario usa `huge_encode_dev`, el kernel `MKDEV` (`MAJOR<<20`); además en btrfs/overlayfs ni siquiera es el mismo dispositivo | Análisis de `include/linux/kdev_t.h` | Conversión `to_kernel_dev()` + comodín `dev=0` (`-i`) |
| 6 | Nombrar un mapa BPF `config` | Choca con un tipo `config` definido en `vmlinux.h` → `error: unexpected type name 'config'` | Error de compilación de clang | Renombrado a `guard_config` |
| 7 | En la prueba de `O_RDONLY+MAP_SHARED+PROT_WRITE`, esperar siempre `EACCES` | Con el guard cargado, `vm_mmap_pgoff()` llama a `security_mmap_file()` **antes** de `do_mmap()`, así que el LSM responde primero con `EPERM` | Lectura de `mm/util.c` antes de ejecutar la fase 2 | La prueba acepta ambos e informa qué capa lo negó |
| 8 | Modificar `vma->vm_flags` directamente (`vma->vm_flags \|= ...`) | Desde 6.3 `vm_flags` es `const` en una unión; hay que usar `vm_flags_set()` | Headers 6.8 (`mm_types.h`) | mmap-guard solo **lee** `vm_flags` (válido en todas las versiones) |
| 10 | Suponer que un programa CO-RE que compila contra el BTF de un kernel compila igual contra cualquier otro | En OrbStack 7.0 + clang 21, `vmlinux.h` trae declaraciones vacías (`struct ns_tree;`) que fallan con `-Werror`, y `vma->vm_file` aparece como `struct file___2 *` (tipo duplicado en el BTF) | `make` en la máquina real (kernel 7.0.14-orbstack) | `#pragma` que silencia solo `-Wmissing-declarations` en el include de `vmlinux.h` y cast explícito de `vm_file` |
| 9 | Usar `/usr/sbin/bpftool` sin más | En Ubuntu es un wrapper que falla si no hay `linux-tools` del kernel exacto | Error en `make bpf` | El Makefile detecta un `bpftool` funcional |

## 3.2 Procedimiento de validación

1. **Firmas contra los headers de la distribución**:
   `grep -n "mmap_file\|file_mprotect" /usr/src/linux-headers-$(uname -r)/include/linux/lsm_hook_defs.h`.
2. **Compilación limpia**: `make clean && make` con `-Wall -Wextra -Werror` (usuario, BPF) y
   `ccflags-y := -Werror` (Kbuild). Cualquier warning rompe el build.
3. **Verificador BPF**: `sudo ./build/mmap_guardd -v` muestra el log del verificador si rechaza
   un programa; las reubicaciones CO-RE se validan contra `/sys/kernel/btf/vmlinux`.
4. **Símbolos del LKM**: `modinfo lkm/pf_monitor.ko` y `dmesg` tras `insmod`; un símbolo no
   exportado aparece como `Unknown symbol`.
5. **Prueba de doble fase**: `sudo ./tests/run_all.sh`: cada ataque debe *funcionar* sin
   guard y *fallar* con él; los controles legítimos deben funcionar siempre.
6. **Descarga segura**: `rmmod pf_monitor` y Ctrl+C del loader con tráfico concurrente
   (`test_concurrency`) sin oops en `dmesg`.
