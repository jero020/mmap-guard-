# Kbuild del módulo pf_monitor.
# Uso: make KDIR=/lib/modules/$(uname -r)/build
obj-m := pf_monitor.o

# Equivalente a -Werror dentro de Kbuild (los warnings rompen el build).
ccflags-y := -Werror

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
