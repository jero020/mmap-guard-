#!/usr/bin/env bash
# bench.sh — Mide el sobrecosto (overhead) de mmap-guard.
#
#   sudo ./tests/bench.sh [iteraciones]
#
# Compara tres configuraciones sobre el mismo archivo:
#   base    : sin nada cargado
#   bpf     : hooks eBPF-LSM (si el kernel lo soporta)
#   lkm     : pf_monitor con kprobe en handle_mm_fault (+ kretprobes si no hay BPF-LSM)
# Para cada una ejecuta bench_mmap (ns/op) y, si existe, `perf stat` sobre la prueba
# de concurrencia. Resultados en results/bench_<fecha>.txt
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ITERS=${1:-100000}
DEMO=${DEMO:-/dev/shm/mmap-guard-bench}
OUT=$ROOT/results/bench_$(date +%Y%m%d_%H%M%S).txt
GUARD_PID=""

[[ $EUID -eq 0 ]] || { echo "Ejecuta con sudo"; exit 2; }
cleanup() {
    [[ -n $GUARD_PID ]] && kill -INT "$GUARD_PID" 2>/dev/null && wait "$GUARD_PID" 2>/dev/null
    rmmod pf_monitor 2>/dev/null || true
}
trap cleanup EXIT

make -C "$ROOT" tests >/dev/null
make -C "$ROOT" bpf loader >/dev/null 2>&1 || echo "(no se pudo compilar la parte BPF)"
[[ -f /lib/modules/$(uname -r)/build/Makefile ]] && make -C "$ROOT" lkm >/dev/null
mkdir -p "$ROOT/results" "$DEMO"
head -c 1048576 /dev/urandom > "$DEMO/protegido.bin"
INO=$(stat -c %i "$DEMO/protegido.bin")
echo "protect $DEMO/protegido.bin" > "$DEMO/bench.conf"
HAS_BPF=0; grep -qw bpf /sys/kernel/security/lsm 2>/dev/null && HAS_BPF=1
# perf en Ubuntu es un wrapper que falla con kernels no estándar (OrbStack): buscar el binario real.
PERF=""
for c in perf /usr/lib/linux-tools/*/perf /usr/lib/linux-tools-*/perf; do
    if command -v "$c" >/dev/null 2>&1 && "$c" stat -e task-clock true >/dev/null 2>&1; then PERF=$c; break; fi
done
HAS_PERF=0; [[ -n $PERF ]] && HAS_PERF=1

measure() {   # measure <etiqueta>
    echo "### $1" | tee -a "$OUT"
    for run in 1 2 3; do
        echo "run $run: $("$ROOT/build/tests/bench_mmap" "$DEMO/protegido.bin" "$ITERS" | tr '\n' ' ')" \
            | tee -a "$OUT"
    done
    if [[ $HAS_PERF -eq 1 ]]; then
        "$PERF" stat -e page-faults,minor-faults,context-switches,task-clock \
            "$ROOT/build/tests/test_concurrency" "$DEMO/protegido.bin" allow 8 2000 \
            2>&1 >/dev/null | grep -E "page-faults|minor|context|task-clock|elapsed" | tee -a "$OUT"
    fi
    echo | tee -a "$OUT"
}

{ echo "# mmap-guard bench — $(date)"; echo "# kernel $(uname -r), iteraciones $ITERS, perf: ${PERF:-no disponible}"; echo; } > "$OUT"

measure "base (sin guard)"

if [[ $HAS_BPF -eq 1 ]]; then
    # -a: auditoría para que la prueba de concurrencia no falle; el costo del hook es el mismo.
    "$ROOT/build/mmap_guardd" -a -c "$DEMO/bench.conf" -i > "$DEMO/guard.log" 2>&1 &
    GUARD_PID=$!; sleep 1
    measure "bpf-lsm (mmap_file + file_mprotect)"
    kill -INT "$GUARD_PID"; wait "$GUARD_PID" 2>/dev/null || true; GUARD_PID=""
fi

if [[ -f $ROOT/lkm/pf_monitor.ko ]]; then
    insmod "$ROOT/lkm/pf_monitor.ko" ino="$INO"
    measure "lkm pf_monitor (kprobe handle_mm_fault)"
    rmmod pf_monitor
else
    echo "(pf_monitor.ko no disponible: se omite la medición del LKM)" | tee -a "$OUT"
fi

echo "Resultados guardados en $OUT"
