# Matriz de compensaciones: rendimiento vs. seguridad

Escala: ●●● alto · ●● medio · ● bajo · — no aplica.
Los costos son órdenes de magnitud esperados; las cifras medidas en el entorno real van en la
sección **Resultados** del README (`tests/bench.sh`).

| Estrategia | Dónde actúa | Costo en `mmap()` | Costo por page fault | Costo por acceso posterior | Cobertura / profundidad | Evadible desde usuario | Riesgo de estabilidad | Requisitos |
|---|---|---|---|---|---|---|---|---|
| Wrapper en usuario (`LD_PRELOAD`) | libc | ● | — | — | ● | **Sí** (syscall directa, binario estático) | ● | ninguno |
| LKM + `sys_call_table` | entrada de syscall | ● | — | — | ●● (faltan rutas compat/internas) | No | **●●●** (CR0, `.rodata`, TOCTOU) | símbolos no exportados |
| **BPF-LSM `mmap_file` + `file_mprotect`** (mmap-guard) | alta/cambio de VMA | ● (~2 búsquedas hash) | — | — | ●● (impide el canal; no inspecciona contenido) | No | ● (verificador) | `CONFIG_BPF_LSM`, `lsm=...,bpf` |
| LKM + kretprobes en `security_*` (respaldo) | wrapper LSM | ●● (trampa int3/ftrace por llamada) | — | — | ●● | No | ●● (depende de no-inline y ABI de registros) | headers, `CONFIG_KRETPROBES` |
| kprobe/fentry en `handle_mm_fault` (pf_monitor) | cada fault | — | ●● (en TODOS los faults del sistema) | — | ● (solo observa el 1er acceso) | No | ● | `CONFIG_KPROBES` |
| Forzar faults en cada escritura (PTE R/O, `userfaultfd-wp`) | cada escritura | ● | **●●●** | **●●●** (un fault por escritura) | ●●● | No | ●● | cambios en el FS/mm |
| Cifrado a nivel FS (fscrypt) | E/S de bloques | — | ●● (descifrado en lectura de disco) | — | ●●● confidencialidad en disco, ● en RAM | No | ● | soporte del FS |
| Cifrado de memoria por hardware (SME/TME/SEV) | controlador de memoria | — | — | ● (latencia DRAM) | ●●● contra ataques físicos | No | ● | CPU/hipervisor |

## Lectura de la matriz

- **El punto óptimo para el objetivo del parcial** (prevenir modificación no autorizada) es
  decidir en el **alta del VMA**: el costo se paga una vez por `mmap()`/`mprotect()` y es
  independiente de cuántas veces se acceda la memoria después. Los accesos siguen a velocidad
  de hardware.
- **Lo que se sacrifica**: no se inspecciona *qué* se escribe. Se elimina el canal (mapeo
  compartido escribible) en lugar de filtrarlo. Las aplicaciones legítimas que necesitan
  `MAP_SHARED|PROT_WRITE` sobre un archivo protegido deben ir en la lista blanca o usar `write()`.
- **Medir faults es caro**: el kprobe en `handle_mm_fault` corre para todos los procesos,
  no solo los que usan archivos protegidos. Por eso `pf_monitor` es una herramienta de
  medición y no parte del camino de defensa.
- **Seguridad total en cada acceso** solo se logra forzando un fault por escritura, lo que
  anula la ventaja de `mmap()` frente a `write()`.
