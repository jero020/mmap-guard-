#!/usr/bin/env bash
# run_all.sh — Compila, carga mmap-guard y ejecuta todas las pruebas (PASS/FAIL).
#
#   sudo ./tests/run_all.sh [--mode auto|bpf|lkm] [--no-build]
#
# Fases:
#   1. Línea base: sin guard, los ataques deben FUNCIONAR (demuestra que el riesgo existe).
#   2. Con guard: los ataques deben fallar con EPERM y los usos legítimos seguir funcionando.
# Modo bpf = hooks eBPF-LSM (requiere "bpf" en /sys/kernel/security/lsm).
# Modo lkm = modo respaldo del módulo pf_monitor (kretprobes).
# Solo se usan archivos temporales creados aquí, en $DEMO.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=$ROOT/build/tests
DEMO=${DEMO:-/dev/shm/mmap-guard-demo}
MODE=auto
BUILD=1
GUARD_PID=""
LKM_LOADED=0
PASS=0
FAIL=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --mode) MODE=$2; shift 2 ;;
        --no-build) BUILD=0; shift ;;
        *) echo "Opción desconocida: $1"; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Ejecuta con sudo"; exit 2; }

cleanup() {
    if [[ -n $GUARD_PID ]] && kill -0 "$GUARD_PID" 2>/dev/null; then
        kill -INT "$GUARD_PID"; wait "$GUARD_PID" 2>/dev/null || true
    fi
    if [[ $LKM_LOADED -eq 1 ]]; then rmmod pf_monitor 2>/dev/null || true; fi
}
trap cleanup EXIT

if [[ $MODE == auto ]]; then
    if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then MODE=bpf; else MODE=lkm; fi
fi
echo "== mmap-guard: modo $MODE =="

if [[ $BUILD -eq 1 ]]; then
    if [[ $MODE == bpf ]]; then make -C "$ROOT" bpf loader tests >/dev/null; fi
    make -C "$ROOT" lkm tests >/dev/null
fi

# --- Archivos de prueba --------------------------------------------------------------
rm -rf "$DEMO"; mkdir -p "$DEMO"
head -c 1048576 /dev/urandom > "$DEMO/secreto.txt"   # protegido contra escritura compartida
head -c 65536   /dev/urandom > "$DEMO/payload.bin"   # protegido contra ejecución
head -c 65536   /dev/urandom > "$DEMO/libre.txt"     # no protegido (control)
chmod 666 "$DEMO"/*
cat > "$DEMO/run.conf" <<CONF
protect $DEMO/secreto.txt
noexec  $DEMO/payload.bin
CONF
INO_S=$(stat -c %i "$DEMO/secreto.txt")
INO_P=$(stat -c %i "$DEMO/payload.bin")

run() {   # run <descripción> <comando...>
    local desc=$1; shift
    if "$@" > "$DEMO/last.log" 2>&1; then
        PASS=$((PASS + 1)); echo "  PASS  $desc"
    else
        FAIL=$((FAIL + 1)); echo "  FAIL  $desc"; sed 's/^/        /' "$DEMO/last.log"
    fi
}

suite() {  # suite <allow|deny>
    local e=$1
    run "mmap shared write   ($e)" "$BIN/test_mmap_shared_write" "$DEMO/secreto.txt" "$e"
    run "mprotect escalation ($e)" "$BIN/test_mprotect_escalation" "$DEMO/secreto.txt" "$e"
    run "mmap exec           ($e)" "$BIN/test_mmap_exec" "$DEMO/payload.bin" "$e"
    run "rdonly private COW"       "$BIN/test_rdonly_private" "$DEMO/secreto.txt"
    run "concurrencia        ($e)" "$BIN/test_concurrency" "$DEMO/secreto.txt" "$e" 8 2000
    run "archivo libre no afectado" "$BIN/test_mmap_shared_write" "$DEMO/libre.txt" allow
}

echo "-- Fase 1: línea base (sin guard)"
suite allow

echo "-- Fase 2: con guard"
if [[ $MODE == bpf ]]; then
    # En btrfs/overlayfs st_dev != s_dev: usar comodín de dispositivo.
    FS=$(stat -f -c %T "$DEMO")
    FLAG=""; [[ $FS == btrfs || $FS == overlayfs ]] && FLAG="-i"
    "$ROOT/build/mmap_guardd" -c "$DEMO/run.conf" $FLAG > "$DEMO/guard.log" 2>&1 &
    GUARD_PID=$!
    for _ in $(seq 50); do
        grep -q "activo" "$DEMO/guard.log" 2>/dev/null && break
        kill -0 "$GUARD_PID" 2>/dev/null || { cat "$DEMO/guard.log"; exit 1; }
        sleep 0.1
    done
    # pf_monitor solo como medición (sin enforce).
    if insmod "$ROOT/lkm/pf_monitor.ko" ino="$INO_S,$INO_P" 2>/dev/null; then LKM_LOADED=1; fi
else
    insmod "$ROOT/lkm/pf_monitor.ko" ino="$INO_S,$INO_P" enforce=1
    LKM_LOADED=1
fi
suite deny

echo
if [[ -n $GUARD_PID ]]; then
    kill -INT "$GUARD_PID"; wait "$GUARD_PID" 2>/dev/null || true; GUARD_PID=""
    echo "-- Últimos eventos de auditoría (de $(grep -c 'pid=' "$DEMO/guard.log" || true)):"
    grep 'pid=' "$DEMO/guard.log" | tail -8 | sed 's/^/  /'
    sed -n '/\[stats\]/,$p' "$DEMO/guard.log" | sed 's/^/  /'
fi
if [[ $LKM_LOADED -eq 1 ]]; then
    echo "-- /proc/mmap_guard_stats:"; sed 's/^/  /' /proc/mmap_guard_stats
fi

echo
echo "== Resultado: $PASS PASS, $FAIL FAIL =="
[[ $FAIL -eq 0 ]]
