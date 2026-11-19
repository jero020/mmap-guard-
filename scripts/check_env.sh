#!/usr/bin/env bash
# check_env.sh — Diagnóstico del entorno para mmap-guard.
# Verifica que el kernel tenga lo necesario para la capa eBPF-LSM y para compilar el LKM.
set -uo pipefail

ok()   { printf '  [OK]   %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; }
fail() { printf '  [FAIL] %s\n' "$1"; }

echo "== Kernel =="
echo "  $(uname -srm)"

echo "== LSM activos =="
if [[ -r /sys/kernel/security/lsm ]]; then
    lsms=$(cat /sys/kernel/security/lsm)
    echo "  $lsms"
    if [[ ",$lsms," == *",bpf,"* ]]; then
        ok "BPF-LSM activo: los hooks lsm/* pueden bloquear"
    else
        fail "BPF-LSM NO está en la lista: se usará el modo respaldo del LKM"
    fi
else
    warn "/sys/kernel/security/lsm no legible (¿securityfs sin montar o sin sudo?)"
fi

echo "== Configuración del kernel =="
cfg=""
for f in /proc/config.gz "/boot/config-$(uname -r)"; do
    [[ -r $f ]] && cfg=$f && break
done
if [[ -n $cfg ]]; then
    reader=cat; [[ $cfg == *.gz ]] && reader=zcat
    for opt in CONFIG_BPF_LSM CONFIG_BPF_SYSCALL CONFIG_DEBUG_INFO_BTF CONFIG_KPROBES \
               CONFIG_KRETPROBES CONFIG_MODULES CONFIG_BPF_KPROBE_OVERRIDE; do
        val=$($reader "$cfg" | grep -E "^$opt=" || true)
        if [[ -n $val ]]; then ok "$val"; else fail "$opt no habilitado"; fi
    done
else
    warn "No se encontró la config del kernel (/proc/config.gz ni /boot/config-*)"
fi

echo "== BTF =="
if [[ -r /sys/kernel/btf/vmlinux ]]; then ok "/sys/kernel/btf/vmlinux disponible (CO-RE)"
else fail "Sin BTF: no se puede generar vmlinux.h"; fi

echo "== Headers para compilar módulos =="
if [[ -d /lib/modules/$(uname -r)/build ]]; then ok "/lib/modules/$(uname -r)/build existe"
else fail "Faltan headers: sudo apt install linux-headers-\$(uname -r)"; fi

echo "== Herramientas =="
for t in clang llc bpftool gcc make perf strace; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t"; else warn "$t no instalado"; fi
done
if pkg-config --exists libbpf 2>/dev/null; then ok "libbpf $(pkg-config --modversion libbpf)"
else warn "libbpf-dev no instalado"; fi
