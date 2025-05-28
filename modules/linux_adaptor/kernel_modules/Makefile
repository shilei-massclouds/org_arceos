CFLAGS := -isystem /usr/lib/gcc-cross/riscv64-linux-gnu/11/include \
	-I./arch/riscv/include -I./arch/riscv/include/generated \
	-I./include \
	-I./arch/riscv/include/uapi -I./arch/riscv/include/generated/uapi -I./include/uapi -I./include/generated/uapi \
	-include ./include/linux/kconfig.h -include ./include/linux/compiler_types.h \
	-nostdinc -fno-PIE -mabi=lp64d -march=rv64imafdc \
    -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -fno-common -fno-stack-protector -mcmodel=medany -D__KERNEL__ \
    -O2 -Wno-stringop-overflow -Wno-format-truncation -Wno-format-security \
    -Werror=implicit-function-declaration -Wno-address-of-packed-member -Werror=implicit-function-declaration

TARGET = libclinux.a

# Original linux modules
OBJS := virtio_blk.o virtio.o
#OBJS += container/virtio_mmio.ko
#OBJS += container/virtio.ko

# Adaptor files, we will re-write them in Rust in future.
OBJS += cl_mine.o main.o sbi.o workqueue.o \
		printk.o vsprintf.o ctype.o kstrtox.o \
		alloc.o genhd.o bus.o klist.o locking.o \
		driver.o

#OBJS += main.o mine.o sbi.o printk.o vsprintf.o ctype.o kstrtox.o \
#		workqueue.o alloc.o genhd.o bus.o klist.o \
#		of_platform.o string.o device.o ida.o sched.o driver.o irq.o \
#		blk_mq.o string_helpers.o block_ops.o bio.o scatterlist.o \
#		paging.o

CROSS_ = riscv64-linux-gnu-
CC = $(CROSS_)gcc
AR = $(CROSS_)ar

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) r $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -DKBUILD_MODFILE='"$@"' -DKBUILD_BASENAME='"$@"' -DKBUILD_MODNAME='"$@"' -c -o $@ $<

clean:
	rm -f *.o libclinux.a
