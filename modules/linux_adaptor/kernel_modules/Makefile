CFLAGS := -isystem /usr/lib/gcc-cross/riscv64-linux-gnu/11/include \
	-I./arch/riscv/include -I./arch/riscv/include/generated \
	-I./include \
	-I./arch/riscv/include/uapi -I./arch/riscv/include/generated/uapi -I./include/uapi -I./include/generated/uapi \
	-include ./include/linux/kconfig.h -include ./include/linux/compiler_types.h \
	-nostdinc -fno-PIE -mabi=lp64d -march=rv64imafdc \
    -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -fno-common -fno-stack-protector -mcmodel=medany -D__KERNEL__ \
    -O2 -Wno-stringop-overflow -Wno-format-truncation -Wno-format-security \
    -Werror=implicit-function-declaration -Wno-address-of-packed-member -Werror=implicit-function-declaration \
    -fno-omit-frame-pointer -Wno-frame-address -Wframe-larger-than=2048

ifeq ("$(LOG)", "debug")
CFLAGS += -DDEBUG
endif

TARGET = libclinux.a

# Original linux modules
OBJS := virtio/virtio_blk.o
OBJS += virtio/virtio.o virtio/virtio_ring.o virtio/virtio_mmio.o
OBJS += virtio/virtio_anchor.o
OBJS += irqchip/irq-sifive-plic.o irqchip/irq-riscv-intc.o
OBJS += spi/spi-sifive.o spi/spi.o spi/spi-mem.o
OBJS += spi-nor/core.o spi-nor/sfdp.o spi-nor/swp.o spi-nor/otp.o
OBJS += spi-nor/issi.o
OBJS += mtd/mtdcore.o mtd/mtdpart.o mtd/mtdblock.o mtd/mtd_blkdevs.o
OBJS += nvmem/core.o nvmem/layouts.o
OBJS += clk/clk-devres.o clk/clkdev.o clk/clk.o clk/sifive-prci.o
OBJS += clk/wrpll-cln28hpc.o

OBJS += init/do_mounts.o init/main.o
OBJS += mm/mm_init.o mm/page_alloc.o mm/filemap.o mm/page-writeback.o
OBJS += mm/slub.o mm/percpu.o mm/slab_common.o mm/util.o mm/swap.o
OBJS += mm/debug_page_alloc.o mm/debug.o mm/ioremap.o mm/mempool.o
OBJS += mm/backing-dev.o mm/list_lru.o mm/shrinker.o mm/memblock.o
OBJS += mm/truncate.o mm/workingset.o mm/readahead.o mm/memory.o
OBJS += mm/rmap.o mm/vmstat.o mm/maccess.o mm/vmalloc.o
OBJS += mm/dma-noncoherent.o	# /arch/riscv/mm/dma-noncoherent.c
OBJS += iomap/fiemap.o iomap/iter.o iomap/trace.o
OBJS += printk/printk.o
OBJS += lib/vsprintf.o lib/string.o lib/hexdump.o lib/ratelimit.o
OBJS += lib/bitmap.o lib/kasprintf.o lib/string_helpers.o lib/list_debug.o
OBJS += lib/radix-tree.o lib/maple_tree.o lib/kobject.o lib/klist.o
OBJS += lib/devres.o lib/hweight.o lib/errname.o lib/idr.o lib/xarray.o
OBJS += lib/sort.o lib/sbitmap.o lib/lockref.o lib/rbtree.o lib/dec_and_lock.o
OBJS += lib/find_bit.o lib/sg_pool.o lib/scatterlist.o lib/errseq.o lib/llist.o
OBJS += lib/crc32.o lib/iov_iter.o lib/irq_regs.o lib/dump_stack.o lib/kstrtox.o
OBJS += lib/percpu_counter.o lib/strncpy_from_user.o lib/ctype.o lib/seq_buf.o
OBJS += lib/cmdline.o
OBJS += lib/delay.o	# arch/riscv/lib/delay.c
OBJS += math/reciprocal_div.o
OBJS += crypto/api.o crypto/algapi.o crypto/blake2s.o crypto/blake2s-generic.o
OBJS += crypto/chacha.o
OBJS += crypto/shash.o crypto/crc32_generic.o crypto/crc32c_generic.o
OBJS += time/timekeeping.o time/timer.o time/hrtimer.o
OBJS += rcu/tree.o rcu/sync.o rcu/srcutree.o
OBJS += sched/core.o sched/wait.o sched/wait_bit.o
OBJS += sched/swait.o sched/completion.o
OBJS += locking/spinlock.o locking/spinlock_debug.o locking/qrwlock.o
OBJS += locking/mutex.o locking/mutex-debug.o
OBJS += locking/rwsem.o locking/percpu-rwsem.o
OBJS += base/platform.o base/property.o base/syscore.o base/bus.o
OBJS += base/core.o base/devres.o base/dd.o base/driver.o base/trace.o
OBJS += base/class.o
OBJS += of/base.o of/property.o of/address.o of/irq.o of/fdt.o
OBJS += of/of_reserved_mem.o of/kobj.o of/platform.o of/device.o
OBJS += irq/irqdomain.o irq/irqdesc.o irq/manage.o irq/dummychip.o
OBJS += irq/resend.o irq/chip.o irq/handle.o irq/msi.o irq/spurious.o
OBJS += irq/devres.o
OBJS += dma/mapping.o dma/swiotlb.o
OBJS += kernel/resource.o kernel/workqueue.o kernel/kthread.o
OBJS += kernel/nsproxy.o kernel/cpu.o kernel/user_namespace.o
OBJS += kernel/panic.o kernel/exit.o kernel/cred.o kernel/softirq.o
OBJS += kernel/extable.o kernel/tracepoint.o kernel/jump_label.o
OBJS += kernel/irq_work.o kernel/params.o
OBJS += kernel/stacktrace.o			# for arch/riscv/kernel
OBJS += kernel/riscv_jump_label.o	# for arch/riscv/kernel
OBJS += kernel/patch.o				# for arch/riscv/kernel
OBJS += block/genhd.o block/blk-mq.o block/blk-mq-virtio.o
OBJS += block/blk-mq-cpumap.o block/blk-mq-tag.o block/blk-core.o
OBJS += block/blk-stat.o block/blk-settings.o block/bio.o
OBJS += block/bdev.o block/fops.o block/blk-merge.o block/blk-mq-sched.o
OBJS += block/blk-flush.o block/blk-mq-sysfs.o block/blk-rq-qos.o
OBJS += block/blk-timeout.o block/early-lookup.o
OBJS += fs/inode.o fs/libfs.o fs/filesystems.o fs/dcache.o fs/sync.o
OBJS += fs/namespace.o fs/fs_context.o fs/super.o fs/mnt_idmapping.o
OBJS += fs/buffer.o fs/file_table.o fs/bad_inode.o fs/mbcache.o
OBJS += fs/read_write.o fs/fs-writeback.o fs/readdir.o fs/posix_acl.o
OBJS += fs/stat.o fs/char_dev.o fs/open.o fs/namei.o fs/file.o fs/exec.o
OBJS += fs/fs_struct.o fs/locks.o fs/d_path.o fs/attr.o
OBJS += char/random.o
OBJS += proc/generic.o
OBJS += trace/trace_syscalls.o trace/trace.o trace/trace_events.o
OBJS += trace/trace_output.o trace/pid_list.o trace/trace_events_filter.o
OBJS += trace/ring_buffer.o trace/ftrace.o trace/trace_seq.o
OBJS += trace/trace_functions.o trace/trace_nop.o
OBJS += libfdt/fdt.o libfdt/fdt_ro.o

#OBJS += fs_types.o
#OBJS += mpage.o

# ext2 fs
#OBJS += ext2/super.o ext2/balloc.o ext2/dir.o ext2/file.o
#OBJS += ext2/ialloc.o ext2/inode.o
#OBJS += ext2/ioctl.o ext2/namei.o ext2/super.o ext2/symlink.o

# ext4 fs
OBJS += ext4/super.o ext4/balloc.o ext4/bitmap.o ext4/block_validity.o
OBJS += ext4/ext4_jbd2.o ext4/extents.o ext4/extents_status.o ext4/file.o ext4/dir.o
OBJS += ext4/fsmap.o ext4/fsync.o ext4/hash.o ext4/ialloc.o ext4/indirect.o
OBJS += ext4/inline.o ext4/inode.o ext4/inode-test.o ext4/ioctl.o ext4/mballoc.o
OBJS += ext4/migrate.o ext4/mmp.o ext4/move_extent.o ext4/namei.o ext4/page-io.o
OBJS += ext4/readpage.o ext4/resize.o ext4/super.o ext4/symlink.o ext4/sysfs.o
OBJS += ext4/verity.o ext4/xattr.o ext4/xattr_hurd.o ext4/orphan.o ext4/acl.o
OBJS += ext4/xattr_trusted.o ext4/xattr_user.o ext4/fast_commit.o
OBJS += ext4/xattr_security.o

# jbd2
OBJS += jbd2/checkpoint.o jbd2/commit.o jbd2/journal.o jbd2/recovery.o
OBJS += jbd2/revoke.o jbd2/transaction.o

# Adaptor files, we will re-write them in Rust in future.
OBJS += cl_mine.o main.o smp.o softirq.o panic.o \
		riscv_irq.o \
		cl_dummy.o \
		mount_ops.o cl_syscalls.o \
		test_block.o test_fs.o
		#signal.o \

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
