CC := $(AX_ARCH)-linux-gnu-gcc
STRIP := $(AX_ARCH)-linux-gnu-strip
INIT := $(AX_ARCH)/init
INIT_STATIC := $(AX_ARCH)/init_static

all: $(INIT) $(INIT_STATIC)

$(INIT): init.c
	$(CC) $< -o $@
	$(STRIP) $@

$(INIT_STATIC): init.c
	$(CC) -static $< -o $@
	$(STRIP) $@

#riscv64-linux-gnu-gcc -static ./main1.c -o hello1 -L/home/cloud/study/glibc-2.36-riscv/build/
