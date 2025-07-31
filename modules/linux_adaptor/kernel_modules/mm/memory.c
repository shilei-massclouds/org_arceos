#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/memremap.h>
#include <linux/kmsan.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
#include <linux/delayacct.h>
#include <linux/init.h>
#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
#include <linux/memory-tiers.h>
#include <linux/debugfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>
#include <linux/oom.h>
#include <linux/numa.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/vmalloc.h>
#include <linux/sched/sysctl.h>

#include <trace/events/kmem.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

#include "pgalloc-track.h"
#include "internal.h"
#include "swap.h"

#if defined(CONFIG_PROVE_LOCKING) || defined(CONFIG_DEBUG_ATOMIC_SLEEP)
void __might_fault(const char *file, int line)
{
    if (pagefault_disabled())
        return;
    __might_sleep(file, line);
    if (current->mm)
        might_lock_read(&current->mm->mmap_lock);
}
EXPORT_SYMBOL(__might_fault);
#endif
