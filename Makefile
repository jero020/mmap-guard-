# Makefile raíz de mmap-guard
#
#   make            -> compila todo (bpf + loader + lkm + tests)
#   make bpf        -> objeto BPF y skeleton
#   make loader     -> demonio mmap_guardd
#   make lkm        -> módulo pf_monitor.ko
#   make tests      -> binarios de prueba en build/tests/
#   make clean
#
# Todo se compila con -Wall -Wextra -Werror: cualquier advertencia rompe el build.

BUILD    := build
ARCH     := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
KVER     ?= $(shell uname -r)
KDIR     ?= /lib/modules/$(KVER)/build

CLANG    ?= clang
CC       ?= gcc
# En Ubuntu /usr/sbin/bpftool es un wrapper que falla si no hay linux-tools para el kernel
# exacto; en ese caso se usa cualquier bpftool real instalado en /usr/lib/linux-tools/.
BPFTOOL  ?= $(or $(shell bpftool version >/dev/null 2>&1 && command -v bpftool),$(firstword $(wildcard /usr/lib/linux-tools/*/bpftool)))
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

CFLAGS   := -O2 -g -Wall -Wextra -Werror -std=gnu11
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror \
              -I bpf -I $(BUILD)
LDLIBS   := -lbpf -lelf -lz

BPF_OBJ  := $(BUILD)/mmap_guard.bpf.o
SKEL     := $(BUILD)/mmap_guard.skel.h
VMLINUX_H := bpf/vmlinux.h
LOADER   := $(BUILD)/mmap_guardd

TEST_SRCS := $(wildcard tests/*.c)
TEST_BINS := $(patsubst tests/%.c,$(BUILD)/tests/%,$(TEST_SRCS))

.PHONY: all bpf loader lkm tests clean

all: bpf loader lkm tests

$(BUILD) $(BUILD)/tests:
	mkdir -p $@

# vmlinux.h se genera desde el BTF del kernel en ejecución (CO-RE). No se versiona.
$(VMLINUX_H):
	@test -n "$(BPFTOOL)" || { echo "ERROR: bpftool no encontrado"; exit 1; }
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp && mv $@.tmp $@

$(BPF_OBJ): bpf/mmap_guard.bpf.c bpf/mmap_guard.h $(VMLINUX_H) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

bpf: $(SKEL)

$(LOADER): loader/mmap_guardd.c bpf/mmap_guard.h $(SKEL) | $(BUILD)
	$(CC) $(CFLAGS) -I bpf -I $(BUILD) $< -o $@ $(LDLIBS)

loader: $(LOADER)

lkm:
	$(MAKE) -C lkm KDIR=$(KDIR)

$(BUILD)/tests/%: tests/%.c tests/common.h | $(BUILD)/tests
	$(CC) $(CFLAGS) $< -o $@ -lpthread

tests: $(TEST_BINS)

clean:
	rm -rf $(BUILD) $(VMLINUX_H)
	$(MAKE) -C lkm KDIR=$(KDIR) clean
