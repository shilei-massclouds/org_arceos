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

ifeq ("$(LOG)", "debug")
CFLAGS += -DDEBUG
endif

TARGET = libclinux.a

# Original linux modules
OBJS := virtio/virtio_blk.o
OBJS += virtio/virtio.o virtio/virtio_ring.o virtio/virtio_mmio.o
OBJS += virtio/virtio_anchor.o
OBJS += irqchip/irq-sifive-plic.o irqchip/irq-riscv-intc.o

OBJS += mm/mm_init.o mm/page_alloc.o mm/filemap.o mm/page-writeback.o
OBJS += mm/slub.o mm/percpu.o mm/slab_common.o mm/util.o
OBJS += mm/debug_page_alloc.o mm/debug.o mm/ioremap.o
OBJS += mm/backing-dev.o mm/list_lru.o mm/shrinker.o mm/memblock.o
OBJS += printk/printk.o
OBJS += lib/vsprintf.o lib/string.o lib/hexdump.o lib/ratelimit.o
OBJS += lib/bitmap.o lib/kasprintf.o lib/string_helpers.o lib/list_debug.o
OBJS += lib/radix-tree.o lib/maple_tree.o lib/kobject.o lib/klist.o
OBJS += lib/devres.o lib/hweight.o lib/errname.o lib/idr.o lib/xarray.o
OBJS += lib/sort.o lib/sbitmap.o lib/lockref.o lib/rbtree.o
OBJS += math/reciprocal_div.o
OBJS += time/timekeeping.o
OBJS += rcu/tree.o
OBJS += sched/core.o sched/wait.o sched/wait_bit.o
OBJS += sched/swait.o
OBJS += locking/spinlock.o locking/spinlock_debug.o
OBJS += locking/mutex.o locking/rwsem.o locking/percpu-rwsem.o
OBJS += base/platform.o base/property.o base/syscore.o base/bus.o
OBJS += base/core.o base/devres.o base/dd.o base/driver.o
OBJS += of/base.o of/property.o of/address.o of/irq.o
OBJS += irq/irqdomain.o irq/irqdesc.o irq/manage.o irq/dummychip.o
OBJS += irq/resend.o irq/chip.o irq/handle.o irq/msi.o
OBJS += dma/mapping.o dma/swiotlb.o
OBJS += kernel/resource.o kernel/workqueue.o kernel/kthread.o
OBJS += kernel/nsproxy.o
OBJS += block/genhd.o block/blk-mq.o block/blk-mq-virtio.o
OBJS += block/blk-mq-cpumap.o block/blk-mq-tag.o block/blk-core.o
OBJS += block/blk-stat.o block/blk-settings.o block/bio.o
OBJS += block/bdev.o
OBJS += fs/inode.o fs/libfs.o fs/filesystems.o fs/dcache.o
OBJS += fs/namespace.o fs/fs_context.o fs/super.o fs/mnt_idmapping.o

#OBJS += filesystems.o fs_types.o backing-dev.o
#OBJS += mpage.o
#OBJS += readdir.o libfs.o sync.o
#OBJS += user_namespace.o
#OBJS += shash.o time.o
#OBJS += swait.o proc.o shmem.o

# ext2 fs
#OBJS += ext2/super.o ext2/balloc.o ext2/dir.o ext2/file.o
#OBJS += ext2/ialloc.o ext2/inode.o
#OBJS += ext2/ioctl.o ext2/namei.o ext2/super.o ext2/symlink.o

# ext4 fs
#OBJS += ext4/super.o ext4/balloc.o ext4/bitmap.o ext4/block_validity.o
#OBJS += ext4/ext4_jbd2.o ext4/extents.o ext4/extents_status.o ext4/file.o ext4/dir.o
#OBJS += ext4/fsmap.o ext4/fsync.o ext4/hash.o ext4/ialloc.o ext4/indirect.o
#OBJS += ext4/inline.o ext4/inode.o ext4/inode-test.o ext4/ioctl.o ext4/mballoc.o
#OBJS += ext4/migrate.o ext4/mmp.o ext4/move_extent.o ext4/namei.o ext4/page-io.o
#OBJS += ext4/readpage.o ext4/resize.o ext4/super.o ext4/symlink.o ext4/sysfs.o
#OBJS += ext4/verity.o ext4/xattr.o ext4/xattr_hurd.o
#OBJS += ext4/xattr_trusted.o ext4/xattr_user.o

# jbd2
#OBJS += jbd2/checkpoint.o
#OBJS += jbd2/commit.o
#OBJS += jbd2/journal.o
#OBJS += jbd2/recovery.o
#OBJS += jbd2/revoke.o
#OBJS += jbd2/transaction.o

# Adaptor files, we will re-write them in Rust in future.
OBJS += cl_mine.o main.o smp.o cpu.o softirq.o panic.o \
		riscv_irq.o \
		cl_dummy.o
		#ctype.o kstrtox.o \
		#percpu-rwsem.o \
		#signal.o \
		#completion.o \
		#scatterlist.o rbtree.o mbcache.o

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
