# mmap-guard

Defensa en la capa de kernel para archivos mapeados con `mmap()`. Usa hooks **eBPF-LSM**
(`mmap_file`, `file_mprotect`) para bloquear escrituras compartidas, mapeos ejecutables y
escaladas de permisos vía `mprotect()` sobre archivos protegidos. Incluye auditoría por
ring buffer y un módulo de kernel (LKM) para medir page faults.

> Parcial 25 % – Sistemas Operativos, EAFIT 2026-2:
> *Seguridad de Archivos en Capa Kernel y mmap*.

## Descripción
_Pendiente._

## Arquitectura
_Pendiente — ver `docs/arquitectura.md`._

## Requisitos
Ejecuta primero el diagnóstico del entorno:

```bash
./scripts/check_env.sh
```

## Compilación
_Pendiente._

## Uso
_Pendiente._

## Pruebas
_Pendiente._

## Resultados
_Pendiente._

## Limitaciones
_Pendiente._
