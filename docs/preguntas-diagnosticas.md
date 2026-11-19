# Parte I — Análisis conceptual y preguntas diagnósticas

> Referencias de código fuente: Linux 6.8 (Ubuntu 24.04). Cuando un detalle cambió entre
> versiones se indica la versión. Las rutas (`mm/mmap.c`, etc.) son del árbol del kernel.
> Donde aplica, se enlaza la parte de **mmap-guard** que demuestra o mitiga el punto.

---

## Pregunta 1 — Mapeo virtual y Page Faults

**¿Cuál es la secuencia exacta de eventos desde `mmap()` hasta el primer page fault?**

### Fase A: la llamada `mmap()` (crea el VMA, no toca memoria física)

1. **Ring 3 → Ring 0.** La instrucción `syscall` salta a `entry_SYSCALL_64`, que guarda los
   registros en `struct pt_regs` y despacha `__x64_sys_mmap` → `ksys_mmap_pgoff()` (`mm/mmap.c`).
2. `ksys_mmap_pgoff()` resuelve el descriptor con `fget(fd)` → obtiene el `struct file`.
3. `vm_mmap_pgoff()` (`mm/util.c`):
   1. **`security_mmap_file(file, prot, flags)`** → recorre los hooks LSM `mmap_file`
      (SELinux, AppArmor, **BPF-LSM de mmap-guard**). Si alguno devuelve error, la syscall
      falla aquí, **antes** de crear nada. → `bpf/mmap_guard.bpf.c: mg_mmap_file`.
   2. Toma `mmap_write_lock(mm)` y llama a `do_mmap()`.
4. `do_mmap()` valida y calcula banderas:
   - Alinea `len`, verifica límites (`RLIMIT_AS`, `max_map_count`).
   - `get_unmapped_area()` elige la dirección virtual (o usa la pedida con `MAP_FIXED`).
   - Traduce `PROT_*`/`MAP_*` a `vm_flags` (`VM_READ|VM_WRITE|VM_EXEC`, `VM_MAYREAD|...`,
     `VM_SHARED|VM_MAYSHARE` para `MAP_SHARED`).
   - Chequea el modo del archivo: `MAP_SHARED + PROT_WRITE` exige `FMODE_WRITE` (si no,
     `-EACCES`); sin `FMODE_WRITE` se quita `VM_MAYWRITE`.
5. `mmap_region()` crea el **`struct vm_area_struct`** (`vm_start`, `vm_end`, `vm_flags`,
   `vm_page_prot = vm_get_page_prot(vm_flags)`, `vm_pgoff`, `vm_file = get_file(file)`),
   llama al `->mmap` del sistema de archivos (`generic_file_mmap()` asigna
   `vma->vm_ops = &generic_file_vm_ops`, cuyo `.fault = filemap_fault`) e inserta el VMA en
   el árbol del proceso (*maple tree* desde 6.1; antes rb-tree + lista).
6. Retorna la dirección. **No se reservó ninguna página física ni se creó ningún PTE**
   (salvo con `MAP_POPULATE` o `mlock`): es paginación por demanda.

### Fase B: el primer acceso (page fault)

7. El proceso lee/escribe `p[0]`. La MMU recorre la tabla de páginas desde `CR3`
   (PGD → P4D → PUD → PMD → PTE). El PTE no existe (bit **P=0**) → excepción **#PF**.
   La CPU guarda la dirección en **`CR2`** y un *error code* (bits P, W/R, U/S, I/D).
8. `exc_page_fault()` → `do_user_addr_fault()` (`arch/x86/mm/fault.c`):
   - Busca el VMA: `lock_vma_under_rcu()` (locks por VMA, 6.4+) o `mmap_read_lock` + `find_vma()`.
   - `access_error()`: compara el tipo de acceso con `vm_flags` (escribir en un VMA sin
     `VM_WRITE` → `SIGSEGV`).
9. **`handle_mm_fault(vma, address, flags, regs)`** (`mm/memory.c`) → `__handle_mm_fault()`
   asigna los niveles intermedios de tabla que falten (`p4d_alloc`, `pud_alloc`, `pmd_alloc`)
   → `handle_pte_fault()` → `do_pte_missing()` → `do_fault()`. Este es el punto que
   instrumenta `lkm/pf_monitor.c`.
10. Según el tipo de fault:
    - **Lectura** → `do_read_fault()` → `__do_fault()` → `vma->vm_ops->fault` =
      **`filemap_fault()`**: busca la *folio* en el page cache (`address_space` del inode);
      si no está, la lee del disco (`->read_folio`, *readahead*) y espera la E/S.
    - **Escritura, `MAP_PRIVATE`** → `do_cow_fault()`: reserva una página anónima, copia el
      contenido del page cache y la mapea escribible (Copy-On-Write).
    - **Escritura, `MAP_SHARED`** → `do_shared_fault()`: llama `->page_mkwrite` (el FS
      reserva bloques), mapea la página del page cache escribible y la marca sucia.
11. `finish_fault()` → `set_pte_at()` instala el PTE (PFN + bits P, R/W, U/S, NX) con el
    *page table lock* tomado; se actualiza la MMU/TLB y se retorna a Ring 3, donde la
    instrucción que falló **se reejecuta**.
12. **Accesos siguientes**: la MMU traduce en hardware (TLB) y el kernel **no participa**.
    Por eso la defensa debe actuar en el alta del VMA (`mmap_file`), en los cambios de
    permisos (`file_mprotect`) o en los faults; nunca en cada acceso.

---

## Pregunta 2 — `MAP_SHARED` vs. `MAP_PRIVATE`

En `struct vm_area_struct` la diferencia vive en `vm_flags` y en cómo se resuelven los faults:

| Aspecto | `MAP_SHARED` | `MAP_PRIVATE` |
|---|---|---|
| `vm_flags` | `VM_SHARED | VM_MAYSHARE` | sin `VM_SHARED` |
| Página tras escritura | la misma *folio* del page cache (`folio->mapping` = `address_space` del inode) | página anónima nueva (`folio->mapping` = `anon_vma`) |
| PTE inicial | escribible si `VM_WRITE` (salvo *write-notify* para rastreo de suciedad) | **siempre de solo lectura**, aunque el VMA tenga `VM_WRITE`: así se detecta la primera escritura y se hace COW |
| Persistencia | sí: writeback lleva las páginas sucias al archivo | no: se pierde en `munmap`/exit |
| Visibilidad entre procesos | inmediata: todos los que mapean el archivo comparten la página física | aislada después del COW; *antes* del COW el proceso sí ve cambios hechos por otros al archivo (POSIX lo deja sin especificar) |
| Requisito sobre el fd | `PROT_WRITE` exige `FMODE_WRITE` | solo `FMODE_READ` |

**Implicaciones de seguridad:**

- Un `MAP_SHARED + PROT_WRITE` es un **canal de escritura al archivo que no pasa por
  `write(2)`**: no lo ven filtros sobre `write()`, `LD_PRELOAD`, ni la mayoría de reglas de
  auditoría basadas en syscalls de E/S. Por eso mmap-guard lo bloquea en `mmap_file`
  (`MG_R_SHARED_WRITE`) y también la escalada posterior con `mprotect` (`MG_R_MPROTECT_WRITE`).
- Memoria compartida entre procesos = superficie para condiciones de carrera (TOCTOU): un
  proceso puede cambiar datos que otro ya validó.
- `MAP_PRIVATE` no modifica el archivo, pero comparte páginas físicas con el page cache hasta
  el COW; un bug en el COW (pregunta 3) convierte un mapeo privado en un canal de escritura.

---

## Pregunta 3 — Copy-On-Write y escalada de privilegios

### Ciclo de vida de una página bajo COW

1. **Compartida de solo lectura.** Tras `mmap(MAP_PRIVATE)` + lectura (o tras `fork()`), el
   PTE apunta a la página del page cache (o a la del padre) con **R/W = 0**. `_mapcount` /
   `_refcount` de la *folio* cuentan cuántos la usan.
2. **Fault de escritura.** La CPU genera #PF con el bit W. `handle_pte_fault()` ve un PTE
   presente sin permiso de escritura en un VMA con `VM_WRITE` → **`do_wp_page()`**.
3. **Decisión reuse/copy.** Si la página es anónima y exclusiva (`PageAnonExclusive`,
   6.0+) se reutiliza (`wp_page_reuse`: solo se activa R/W). Si no, **`wp_page_copy()`**:
   reserva página nueva, copia 4 KiB, instala el PTE escribible apuntando a la copia,
   decrementa el *mapcount* de la original y hace flush del TLB.
4. **Privada.** La copia es anónima (`anon_vma`), nunca se escribe al archivo; se puede
   descartar con `MADV_DONTNEED` (vuelve a la fase 1 en el siguiente acceso) o liberar con `munmap`.

### Cuándo una falla en las banderas causa escalada o corrupción

La invariante es: **una escritura a un mapeo privado nunca debe llegar a la página del page
cache**, y una escritura compartida exige `VM_MAYWRITE` (que solo existe si el fd se abrió con
`FMODE_WRITE`). Si el kernel la rompe, un usuario sin privilegios puede modificar archivos
que solo puede leer (`/etc/passwd`, binarios *setuid*), lo que equivale a root.

**Dirty COW (CVE-2016-5195, 2007–2016):** `get_user_pages()` con `FOLL_WRITE | FOLL_FORCE`
(usado por `write()` sobre `/proc/self/mem` y `ptrace`) permite escribir en mapeos
`PROT_READ` privados forzando un COW. En `faultin_page()`, tras romper el COW, el kernel
**quitaba `FOLL_WRITE`** para no entrar en un bucle. Un segundo hilo hacía
`madvise(MADV_DONTNEED)` en la ventana entre el COW y el reintento: la copia privada se
descartaba, el reintento (ya sin `FOLL_WRITE`) resolvía el PTE hacia la **página original del
page cache** y la escritura de `/proc/self/mem` caía ahí → se modificaba el archivo.
- Parche 2016 (`19be0eaffa3a`): bandera `FOLL_COW` + chequeo de `pte_dirty()`.
- Rediseño 2022 (6.0, D. Hildenbrand): se elimina `FOLL_COW`; GUP con `FOLL_WRITE` sobre un
  mapeo privado exige una página anónima exclusiva (`can_follow_write_pte()`).
- Variantes de la misma clase: *Huge Dirty COW* (CVE-2017-1000405, THP) y *Dirty Pipe*
  (CVE-2022-0847, bandera `PIPE_BUF_FLAG_CAN_MERGE` sin inicializar que permitía escribir en
  páginas del page cache de archivos de solo lectura).

**Relación con mmap-guard:** las pruebas `test_rdonly_private` y `test_concurrency` reproducen
la *forma* de esa carga (escritura privada + `MADV_DONTNEED` concurrente) sin el vector de
`/proc/self/mem`, y verifican por hash que el archivo no cambia.

---

## Pregunta 4 — LKM con hook en `sys_call_table` vs. LSM

| Criterio | LKM + `sys_call_table` | LSM (`mmap_file`, `file_mprotect`) |
|---|---|---|
| Viabilidad en 5.x/6.x | **Muy baja.** `sys_call_table` no se exporta; `kallsyms_lookup_name()` dejó de exportarse en 5.7; la tabla está en `.rodata` (`CONFIG_STRICT_KERNEL_RWX`) | Soportado oficialmente |
| Escribir la tabla | Exige quitar el bit **WP de CR0**: no es atómico entre CPUs, deja todo el kernel escribible y desde 5.3 el *CR0 pinning* restaura WP automáticamente | No aplica |
| Qué ve | Argumentos crudos (`fd`, `prot`, `flags`) en `pt_regs` (desde 4.17); debe resolver el fd él mismo → TOCTOU | El `struct file` ya resuelto, la `prot` efectiva y el VMA |
| Cobertura | Solo la entrada que parcheó; faltan `mmap2`, `compat` 32 bits, `remap_file_pages`, rutas internas del kernel | Todas las rutas pasan por `security_mmap_file()`/`security_file_mprotect()` |
| Estabilidad | Rompe con cada cambio de ABI interno; *taint*; incompatible con CFI/IBT | ABI de hooks estable y apilable |
| Carga dinámica | Sí (pero frágil) | LSMs clásicos **no** son módulos (desde 4.2 `security_add_hooks` es `__init` y la lista es `__ro_after_init`); **BPF-LSM** (5.7+) da políticas cargables sin recompilar |

Nota de nomenclatura: el hook histórico `file_mmap` se dividió en 3.5 en **`mmap_addr`** y
**`mmap_file`**; los kernels modernos no tienen `file_mmap`.

**Decisión de mmap-guard:** BPF-LSM como mecanismo principal. El modo respaldo del LKM usa
**kretprobes** sobre `security_mmap_file`/`security_file_mprotect` (no la tabla de
syscalls, no CR0), aceptando que es menos robusto que un LSM real.

---

## Pregunta 5 — Cifrado transparente en memoria

El contenido debe descifrarse **una sola vez, en el límite entre el dispositivo de bloques
y el page cache**, y el aislamiento del texto plano en RAM lo dan las tablas de páginas y el
control de acceso, no el cifrado:

1. **Lectura** (`fscrypt` en ext4/f2fs/ubifs): en la ruta `->read_folio`/`readahead`, cuando
   termina el *bio*, `fscrypt_decrypt_pagecache_blocks()` descifra en la folio del page cache
   (o se usa *inline crypto* del controlador, `blk-crypto`). El page cache contiene texto plano
   → `filemap_fault()` puede mapearlo directamente y `mmap()` funciona sin cambios.
2. **Escritura**: en `->writepages`, `fscrypt_encrypt_pagecache_blocks()` cifra en una
   **página de rebote (*bounce page*)**, nunca en la página del page cache: así un proceso
   que tiene el archivo mapeado no ve texto cifrado ni se rompe su mapeo.
3. **Quién puede ver el texto plano**: solo procesos que abren el archivo (permisos POSIX +
   LSM) y cuya clave está en el *keyring* del FS. Otros procesos no tienen PTEs hacia esas
   páginas → la MMU (U/S, espacios de direcciones separados) los aísla. Al quitar la clave
   (`FS_IOC_REMOVE_ENCRYPTION_KEY`) el kernel **expulsa** esas páginas del page cache.
4. **Lo que el software no cubre**: root, el propio kernel, DMA y ataques físicos (*cold
   boot*) ven el texto plano en RAM. Mitigaciones: `memfd_secret()` (5.14, saca las páginas
   del *direct map* del kernel), cifrado de memoria por hardware **AMD SME/SEV** e **Intel
   TME/MKTME/TDX**, IOMMU para DMA.

Alternativa por bloques (`dm-crypt`): mismo resultado, el page cache también tiene texto
plano; la diferencia es la granularidad (todo el volumen vs. por archivo/directorio).

---

## Pregunta 6 — `msync`/`fsync` y páginas sucias

**Cómo se rastrea la suciedad de un `MAP_SHARED`:**
1. Si el FS necesita saber cuándo se escribe (`vma_wants_writenotify()`), el PTE inicial es de
   solo lectura aun con `VM_WRITE`.
2. La primera escritura provoca un fault → `do_shared_fault()`/`wp_page_shared()` →
   **`->page_mkwrite()`** (el FS reserva bloques, espera writeback en curso) → PTE con R/W=1 y
   bit **D (dirty)** → `folio_mark_dirty()` etiqueta la folio en el `address_space`.
3. Las escrituras siguientes a esa página **no generan faults**.
4. El writeback (hilos `flush`/`wb_workfn` según `dirty_expire_centisecs` ≈ 30 s y
   `dirty_background_ratio`) o **`msync(MS_SYNC)`/`fsync()`** → `vfs_fsync_range()` →
   `filemap_write_and_wait_range()` → `->writepages`. Antes de escribir,
   `folio_clear_dirty_for_io()` → `folio_mkclean()` **vuelve a proteger los PTE** contra
   escritura, para que cualquier escritura posterior genere otro fault (páginas estables durante la E/S).
5. `fsync` además asegura metadatos y el *flush* de la caché del disco (`REQ_PREFLUSH`/FUA).

**Cómo se evade un filtro de seguridad:** el kernel solo tiene oportunidad de inspeccionar
**una vez por página por ciclo de writeback** (en `page_mkwrite`). Entre ese fault y el
writeback el atacante escribe a velocidad de hardware lo que quiera: un filtro que
inspeccione en `page_mkwrite` ve el contenido *viejo*, y uno basado en `write()`/fanotify no
ve nada (las escrituras vía mmap no generan `FAN_MODIFY` por byte). La inspección tendría que
hacerse en `->writepages` (y aun así el contenido ya pudo ser leído por otros procesos que
comparten la página). mmap-guard elige **prevenir** el canal (no permitir mapeos compartidos
escribibles de archivos protegidos) en lugar de inspeccionarlo.

---

## Pregunta 7 — Control de accesos con eBPF (sin recompilar el kernel)

- **BTF + CO-RE**: el kernel publica sus tipos en `/sys/kernel/btf/vmlinux`; `libbpf`
  reubica en tiempo de carga los offsets de `struct file`, `inode`, `vm_area_struct`. El mismo
  `.o` corre en distintos kernels → no hay que recompilar ni el kernel ni el programa.
- **Verificador**: garantiza terminación, accesos acotados y uso correcto de helpers antes de
  ejecutar en Ring 0 (por eso no puede provocar *kernel panic* como un LKM con un bug).
- **Puntos de enganche útiles**:
  - `lsm/mmap_file`, `lsm/file_mprotect` (BPF-LSM, 5.7+): **auditar y denegar**. Es lo que usa
    `bpf/mmap_guard.bpf.c`.
  - `fentry/fexit` (5.5+, trampolinas BPF, menor costo que kprobes) o `kprobe`/`kretprobe` sobre
    `handle_mm_fault`, `filemap_fault`, `do_wp_page`, `madvise_vma_behavior`: **medir** faults,
    COW y descartes. `fexit` ve también el valor de retorno.
  - Tracepoints estables: `syscalls:sys_enter_mmap`, `exceptions:page_fault_user`.
- **Patrones anómalos detectables**: tasa alta de `MADV_DONTNEED` + faults de escritura sobre
  la misma dirección (firma de Dirty COW), escrituras a `/proc/<pid>/mem`, `mprotect` que agrega
  `PROT_EXEC` a páginas de archivo (inyección), mapeos compartidos escribibles de archivos
  sensibles. El ring buffer (`BPF_MAP_TYPE_RINGBUF`, 5.8+) los envía a usuario en orden y sin
  copias por CPU.
- **Límite**: eBPF solo ve *eventos del kernel*; los accesos con el PTE ya instalado son
  invisibles. Para muestrear habría que forzar faults (bits *soft-dirty* con `clear_refs`,
  `userfaultfd` en modo *write-protect*).

---

## Pregunta 8 — Evasión de permisos POSIX (`O_RDONLY` + `PROT_WRITE` + `MAP_PRIVATE`)

**Sí, el kernel lo permite siempre** (no depende de configuración). En `do_mmap()`:

```c
case MAP_SHARED:  /* y MAP_SHARED_VALIDATE */
    if (prot & PROT_WRITE) && !(file->f_mode & FMODE_WRITE)  -> return -EACCES;
    if (!(file->f_mode & FMODE_WRITE)) vm_flags &= ~(VM_MAYWRITE | VM_SHARED);
case MAP_PRIVATE:
    if (!(file->f_mode & FMODE_READ)) -> return -EACCES;   /* solo exige lectura */
```

**Por qué es correcto:** con `MAP_PRIVATE` las escrituras son COW sobre páginas anónimas del
propio proceso; semánticamente equivale a `read()` del archivo a un buffer propio y
modificar el buffer. El permiso de escritura del archivo protege *al archivo*, y el archivo
no cambia. `VM_MAYWRITE` queda activo, así que también se permite `mprotect(PROT_WRITE)`.

**Riesgos:**
- *Alteración temporal*: el proceso ve una versión modificada (p. ej. parchear en memoria una
  configuración o una biblioteca de solo lectura); afecta solo a ese proceso y a sus hijos
  tras `fork()` (comparten las páginas COW hasta su propia escritura).
- *Fuga de información*: antes del COW el mapeo comparte la página física con el page cache,
  así que el proceso ve los cambios que otros escriben en el archivo.
- *Amplificador de bugs*: es exactamente el escenario de Dirty COW; con un fallo del COW la
  escritura "privada" termina en el archivo.
- `/proc/self/mem` + `FOLL_FORCE` permite escribir incluso en mapeos `PROT_READ`.

**Demostración:** `tests/test_rdonly_private.c` verifica que (1) `MAP_SHARED+PROT_WRITE` con
`O_RDONLY` falla (`EACCES` por `do_mmap`, o `EPERM` si mmap-guard decide antes, porque
`security_mmap_file()` se ejecuta antes que `do_mmap()`), (2) `MAP_PRIVATE+PROT_WRITE` funciona
y la escritura es visible en el proceso, (3) el hash del archivo leído con `read()` no cambia.

---

## Pregunta 9 — Carreras entre `madvise(MADV_DONTNEED)` y escrituras privadas

Mecanismos actuales:
1. **`mmap_lock` / locks por VMA**: `madvise(MADV_DONTNEED)` toma `mmap_read_lock`, al igual
   que los faults, así que pueden correr en paralelo; lo que los serializa es el siguiente nivel.
2. **Page table lock (PTL)**: `zap_pte_range()` y `do_wp_page()`/`finish_fault()` toman el
   spinlock de la página de tablas (`pte_offset_map_lock`). Tras tomarlo, el fault
   **revalida** con `pte_same(orig_pte, *ptep)`: si el zap cambió el PTE, el fault se
   descarta y se reintenta desde el principio (no instala nada sobre un estado viejo).
3. **`mmu_gather` y TLB**: el zap acumula las páginas, hace *flush* de TLB en todas las CPUs
   que usan el `mm` y **solo después** libera las páginas, así ninguna CPU puede seguir
   escribiendo por una entrada TLB obsoleta en una página reutilizada.
4. **Refcount/mapcount y folio lock**: una página no se libera mientras alguien (incluido
   GUP) tenga referencia.
5. **GUP con `FOLL_WRITE`** (la ruta de Dirty COW): desde 6.0 solo se sigue un PTE escribible
   si la página es **anónima exclusiva** (`PageAnonExclusive`); si `MADV_DONTNEED` la
   descartó, GUP vuelve a provocar el fault de escritura y obtiene una nueva copia COW. Ya no
   se "olvida" `FOLL_WRITE` en el reintento.

**Verificación en mmap-guard:** `tests/test_concurrency.c` lanza hilos que escriben en mapeos
privados y hacen `MADV_DONTNEED` mientras otros intentan mapeos compartidos escribibles;
comprueba que no hay oops, que el guard deniega el 100 % de los intentos compartidos y que el
hash del archivo no cambia.

---

## Pregunta 10 — `struct page`, tablas de páginas y bits de la MMU

- **`struct page` / `struct folio`** (`include/linux/mm_types.h`): metadatos de **cada marco
  físico**: `flags` (`PG_locked`, `PG_dirty`, `PG_writeback`, `PG_anon_exclusive`...),
  `_refcount`, `_mapcount` (cuántos PTE lo mapean), `mapping` (el `address_space` del inode
  para page cache, o el `anon_vma` con el bit `PAGE_MAPPING_ANON`) e `index`. Permite saber si
  una página es de archivo o anónima, compartida o exclusiva: base de las decisiones de COW.
- **Jerarquía de tablas (x86_64)**: `CR3` → **PGD** → **P4D** (plegado salvo con 5 niveles,
  `LA57`) → **PUD** → **PMD** → **PTE** → marco de 4 KiB (PMD/PUD pueden mapear páginas de
  2 MiB/1 GiB con el bit PS). Cada proceso tiene su PGD → **espacios de direcciones aislados**:
  un proceso solo alcanza los marcos para los que tiene PTE.
- **Bits de protección del PTE** que contienen la inyección de código:

| Bit | Posición | Función |
|---|---|---|
| P | 0 | presente; si 0 → #PF (paginación por demanda) |
| **R/W** | 1 | 0 = solo lectura. COW y rastreo de suciedad lo usan para atrapar la primera escritura |
| **U/S** | 2 | 0 = solo supervisor: Ring 3 no puede acceder a páginas del kernel |
| A / D | 5 / 6 | accedida / sucia (writeback, reclaim) |
| **NX/XD** | 63 | no ejecutable (requiere `EFER.NXE`): ejecutar datos → #PF → `SIGSEGV` |

- **W^X**: `vm_get_page_prot(vm_flags)` traduce `VM_*` a bits del PTE (`protection_map`). Un
  VMA sin `VM_EXEC` tiene NX=1 en todos sus PTE: código inyectado en un buffer de datos no se
  puede ejecutar. El atacante necesita entonces **conseguir una página escribible y
  ejecutable**, o mapear un archivo con código propio con `PROT_EXEC`, o hacer `mprotect(+X)`.
  mmap-guard cierra esas dos últimas rutas para archivos marcados (`noexec`, `MG_R_EXEC`,
  `MG_R_MPROTECT_EXEC`).
- Refuerzos de hardware relacionados: **SMEP/SMAP** (CR4) impiden que el kernel ejecute o
  lea páginas de usuario sin intención; **PKU** (claves de protección por página); **KPTI**
  separa las tablas de usuario y kernel (Meltdown); `CONFIG_STRICT_KERNEL_RWX` aplica W^X al
  propio kernel (por eso no se puede parchear `sys_call_table` sin tocar CR0).
