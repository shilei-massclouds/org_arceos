# Top Makefile

include $(CURDIR)/scripts/Makefile.include

TARGET = libclinux.a

OBJS :=
# Original linux modules

OBJS += mm/mm_init.o mm/page_alloc.o mm/filemap.o mm/page-writeback.o
OBJS += mm/slub.o mm/percpu.o mm/slab_common.o mm/util.o mm/swap.o
OBJS += mm/debug_page_alloc.o mm/debug.o mm/ioremap.o mm/mempool.o
OBJS += mm/backing-dev.o mm/list_lru.o mm/shrinker.o mm/memblock.o
OBJS += mm/truncate.o mm/workingset.o mm/readahead.o mm/memory.o
OBJS += mm/rmap.o mm/vmstat.o mm/maccess.o mm/vmalloc.o mm/dmapool.o
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
OBJS += lib/cmdline.o lib/logic_pio.o
OBJS += lib/delay.o	# arch/riscv/lib/delay.c
OBJS += math/reciprocal_div.o
OBJS += crypto/api.o crypto/algapi.o crypto/blake2s.o crypto/blake2s-generic.o
OBJS += crypto/chacha.o
OBJS += crypto/shash.o crypto/crc32_generic.o crypto/crc32c_generic.o
OBJS += time/timekeeping.o time/timer.o time/hrtimer.o time/time.o
OBJS += rcu/tree.o rcu/sync.o rcu/srcutree.o
OBJS += sched/core.o sched/wait.o sched/wait_bit.o
OBJS += sched/swait.o sched/completion.o
OBJS += locking/spinlock.o locking/spinlock_debug.o locking/qrwlock.o
OBJS += locking/mutex.o locking/mutex-debug.o
OBJS += locking/rwsem.o locking/percpu-rwsem.o
OBJS += of/base.o of/property.o of/address.o of/irq.o of/fdt.o
OBJS += of/of_reserved_mem.o of/kobj.o of/platform.o of/device.o
OBJS += irq/irqdomain.o irq/irqdesc.o irq/manage.o irq/dummychip.o
OBJS += irq/resend.o irq/chip.o irq/handle.o irq/msi.o irq/spurious.o
OBJS += irq/devres.o irq/pm.o irq/affinity.o
OBJS += dma/mapping.o dma/swiotlb.o dma/direct.o dma/coherent.o
OBJS += dma/pool.o
OBJS += kernel/resource.o kernel/workqueue.o kernel/kthread.o
OBJS += kernel/nsproxy.o kernel/cpu.o kernel/user_namespace.o
OBJS += kernel/panic.o kernel/exit.o kernel/cred.o kernel/softirq.o
OBJS += kernel/extable.o kernel/tracepoint.o kernel/jump_label.o
OBJS += kernel/irq_work.o kernel/params.o kernel/reboot.o
OBJS += kernel/notifier.o kernel/smp.o kernel/async.o
OBJS += kernel/stacktrace.o			# for arch/riscv/kernel
OBJS += kernel/riscv_jump_label.o	# for arch/riscv/kernel
OBJS += kernel/patch.o				# for arch/riscv/kernel
OBJS += kernel/reset.o				# for arch/riscv/kernel
OBJS += kernel/riscv_smp.o			# for arch/riscv/kernel
OBJS += kernel/setup.o				# for arch/riscv/kernel
OBJS += kernel/irq.o				# for arch/riscv/kernel
OBJS += kernel/sbi.o kernel/sbi_ecall.o kernel/sbi-ipi.o	# for arch/riscv/kernel
OBJS += block/genhd.o block/blk-mq.o block/blk-mq-virtio.o
OBJS += block/blk-mq-cpumap.o block/blk-mq-tag.o block/blk-core.o
OBJS += block/blk-stat.o block/blk-settings.o block/bio.o
OBJS += block/bdev.o block/fops.o block/blk-merge.o block/blk-mq-sched.o
OBJS += block/blk-flush.o block/blk-mq-sysfs.o block/blk-rq-qos.o
OBJS += block/blk-timeout.o block/early-lookup.o block/blk-map.o
OBJS += block/elevator.o block/mq-deadline.o
OBJS += proc/generic.o
OBJS += trace/trace_syscalls.o trace/trace.o trace/trace_events.o
OBJS += trace/trace_output.o trace/pid_list.o trace/trace_events_filter.o
OBJS += trace/ring_buffer.o trace/ftrace.o trace/trace_seq.o
OBJS += trace/trace_functions.o trace/trace_nop.o
OBJS += libfdt/fdt.o libfdt/fdt_ro.o

# Adaptor files, we will re-write them in Rust in future.
OBJS += cl_mine.o main.o softirq.o \
		riscv_irq.o \
		cl_dummy.o \
		mount_ops.o cl_syscalls.o \
		test_block.o test_fs.o

obj-y := init/ drivers/ fs/

OBJ_LIST := $(patsubst %/, %/obj_list.txt, $(obj-y))

_OBJS = $(shell cat $(OBJ_LIST) | xargs)

all: $(TARGET)

$(TARGET): $(OBJS) $(OBJ_LIST)
	$(Q)rm -f $@
	$(Q)$(AR) r $@ $(OBJS) $(_OBJS)

$(OBJ_LIST): FORCE
	$(Q)$(MAKE) --no-print-directory -f ./scripts/Makefile.build obj=$@

%.o: %.c
	$(CC) $(CFLAGS) -DKBUILD_MODFILE='"$@"' -DKBUILD_BASENAME='"$@"' -DKBUILD_MODNAME='"$@"' -c -o $@ $<

%/%.o: %/%.c
	$(CC) $(CFLAGS) -DKBUILD_MODFILE='"$@"' -DKBUILD_BASENAME='"$@"' -DKBUILD_MODNAME='"$@"' -c -o $@ $<

clean:
	$(Q)rm -f libclinux.a
	$(Q)find . -name "*.o" | xargs rm -f
	$(Q)find . -name "*.txt" | xargs rm -f

FORCE:

.PHONY: all clean FORCE
