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

OBJS += filesystems.o blkdev.o fs_types.o
OBJS += super.o inode.o dcache.o buffer.o filemap.o mpage.o
OBJS += readdir.o read_write.o libfs.o
OBJS += user_namespace.o utils.o
OBJS += swap.o mempool.o shash.o timer.o
OBJS += wait.o swait.o kobject.o proc.o

# ext2 fs
OBJS += ext2/super.o ext2/balloc.o ext2/dir.o ext2/file.o
OBJS += ext2/ialloc.o ext2/inode.o
OBJS += ext2/ioctl.o ext2/namei.o ext2/super.o ext2/symlink.o

# ext4 fs
OBJS += ext4/super.o ext4/balloc.o ext4/bitmap.o ext4/block_validity.o
OBJS += ext4/ext4_jbd2.o ext4/extents.o ext4/extents_status.o ext4/file.o ext4/dir.o
OBJS += ext4/fsmap.o ext4/fsync.o ext4/hash.o ext4/ialloc.o ext4/indirect.o
OBJS += ext4/inline.o ext4/inode.o ext4/inode-test.o ext4/ioctl.o ext4/mballoc.o
OBJS += ext4/migrate.o ext4/mmp.o ext4/move_extent.o ext4/namei.o ext4/page-io.o
OBJS += ext4/readpage.o ext4/resize.o ext4/super.o ext4/symlink.o ext4/sysfs.o
OBJS += ext4/verity.o ext4/xattr.o ext4/xattr_hurd.o
OBJS += ext4/xattr_trusted.o ext4/xattr_user.o

# jbd2
OBJS += jbd2/checkpoint.o
OBJS += jbd2/commit.o
OBJS += jbd2/journal.o
OBJS += jbd2/recovery.o
OBJS += jbd2/revoke.o
OBJS += jbd2/transaction.o

# Adaptor files, we will re-write them in Rust in future.
OBJS += cl_mine.o main.o workqueue.o \
		printk.o vsprintf.o ctype.o kstrtox.o \
		alloc.o genhd.o bus.o klist.o locking.o \
		driver.o of_platform.o dma.o string.o \
		device.o ida.o sched.o irq.o blk_mq.o \
		string_helpers.o block_ops.o bio.o \
		scatterlist.o fiemap.o rbtree.o mbcache.o \
		kthread.o percpu.o

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
