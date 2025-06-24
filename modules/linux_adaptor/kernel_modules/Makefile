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
OBJS := virtio_blk.o virtio.o virtio_mmio.o virtio_ring.o
OBJS += irq-sifive-plic.o
OBJS += irq-sifive-plic.o

OBJS += filesystems.o blkdev.o
OBJS += super.o inode.o dcache.o buffer.o filemap.o
OBJS += user_namespace.o utils.o
# ext2 fs
OBJS += ext2/super.o ext2/balloc.o ext2/dir.o ext2/file.o
OBJS += ext2/ialloc.o ext2/inode.o
OBJS += ext2/ioctl.o ext2/namei.o ext2/super.o ext2/symlink.o

# Adaptor files, we will re-write them in Rust in future.
OBJS += cl_mine.o main.o workqueue.o \
		printk.o vsprintf.o ctype.o kstrtox.o \
		alloc.o genhd.o bus.o klist.o locking.o \
		driver.o of_platform.o dma.o string.o \
		device.o ida.o sched.o irq.o blk_mq.o \
		string_helpers.o block_ops.o bio.o \
		scatterlist.o

CROSS_ = $(ARCH)-linux-musl-
CC = $(CROSS_)gcc
AR = $(CROSS_)ar

all: $(TARGET)

$(TARGET): $(OBJS)
	rm -f $@
	$(AR) r $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -DKBUILD_MODFILE='"$@"' -DKBUILD_BASENAME='"$@"' -DKBUILD_MODNAME='"$@"' -c -o $@ $<

%/%.o: %/%.c
	$(CC) $(CFLAGS) -DKBUILD_MODFILE='"$@"' -DKBUILD_BASENAME='"$@"' -DKBUILD_MODNAME='"$@"' -c -o $@ $<

clean:
	rm -f *.o */*.o libclinux.a

.PHONY: all clean
