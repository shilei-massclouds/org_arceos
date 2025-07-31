#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/init.h>
#include <linux/backing-dev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/blkdev.h>
#include <linux/mpage.h>
#include <linux/rmap.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/pagevec.h>
#include <linux/timer.h>
#include <linux/sched/rt.h>
#include <linux/sched/signal.h>
#include <linux/mm_inline.h>
#include <trace/events/writeback.h>

#include "internal.h"

/*
 * The interval between `kupdate'-style writebacks
 */
unsigned int dirty_writeback_interval = 5 * 100; /* centiseconds */

/*
 * Flag that puts the machine in "laptop mode". Doubles as a timeout in jiffies:
 * a full sync is triggered after this time elapses without any disk activity.
 */
int laptop_mode;

/*
 * We've spun up the disk and we're in laptop mode: schedule writeback
 * of all dirty data a few seconds from now.  If the flush is already scheduled
 * then push it back - the user is still using the disk.
 */
void laptop_io_completion(struct backing_dev_info *info)
{
    //mod_timer(&info->laptop_mode_wb_timer, jiffies + laptop_mode);
    pr_err("%s: No impl.", __func__);
}

/*
 * Called early on to tune the page writeback dirty limits.
 *
 * We used to scale dirty pages according to how total memory
 * related to pages that could be allocated for buffers.
 *
 * However, that was when we used "dirty_ratio" to scale with
 * all memory, and we don't do that any more. "dirty_ratio"
 * is now applied to total non-HIGHPAGE memory, and as such we can't
 * get into the old insane situation any more where we had
 * large amounts of dirty pages compared to a small amount of
 * non-HIGHMEM memory.
 *
 * But we might still want to scale the dirty_ratio by how
 * much memory the box has..
 */
void __init page_writeback_init(void)
{
#if 0
    BUG_ON(wb_domain_init(&global_wb_domain, GFP_KERNEL));

    cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/writeback:online",
              page_writeback_cpu_online, NULL);
    cpuhp_setup_state(CPUHP_MM_WRITEBACK_DEAD, "mm/writeback:dead", NULL,
              page_writeback_cpu_online);
#ifdef CONFIG_SYSCTL
    register_sysctl_init("vm", vm_page_writeback_sysctls);
#endif
#endif
    pr_err("%s: No impl.", __func__);
}

/**
 * balance_dirty_pages_ratelimited - balance dirty memory state.
 * @mapping: address_space which was dirtied.
 *
 * Processes which are dirtying memory should call in here once for each page
 * which was newly dirtied.  The function will periodically check the system's
 * dirty state and will initiate writeback if needed.
 *
 * Once we're over the dirty memory limit we decrease the ratelimiting
 * by a lot, to prevent individual processes from overshooting the limit
 * by (ratelimit_pages) each.
 */
void balance_dirty_pages_ratelimited(struct address_space *mapping)
{
    pr_err("%s: No impl.", __func__);
    //balance_dirty_pages_ratelimited_flags(mapping, 0);
}

/**
 * folio_wait_stable() - wait for writeback to finish, if necessary.
 * @folio: The folio to wait on.
 *
 * This function determines if the given folio is related to a backing
 * device that requires folio contents to be held stable during writeback.
 * If so, then it will wait for any pending writeback to complete.
 *
 * Context: Sleeps.  Must be called in process context and with
 * no spinlocks held.  Caller should hold a reference on the folio.
 * If the folio is not locked, writeback may start again after writeback
 * has finished.
 */
void folio_wait_stable(struct folio *folio)
{
    if (mapping_stable_writes(folio_mapping(folio)))
        folio_wait_writeback(folio);
}

/*
 * Helper function for set_page_dirty family.
 *
 * Caller must hold folio_memcg_lock().
 *
 * NOTE: This relies on being atomic wrt interrupts.
 */
static void folio_account_dirtied(struct folio *folio,
        struct address_space *mapping)
{
    pr_err("%s: No impl.", __func__);
}

/*
 * Mark the folio dirty, and set it dirty in the page cache.
 *
 * If warn is true, then emit a warning if the folio is not uptodate and has
 * not been truncated.
 *
 * The caller must hold folio_memcg_lock().  It is the caller's
 * responsibility to prevent the folio from being truncated while
 * this function is in progress, although it may have been truncated
 * before this function is called.  Most callers have the folio locked.
 * A few have the folio blocked from truncation through other means (e.g.
 * zap_vma_pages() has it mapped and is holding the page table lock).
 * When called from mark_buffer_dirty(), the filesystem should hold a
 * reference to the buffer_head that is being marked dirty, which causes
 * try_to_free_buffers() to fail.
 */
void __folio_mark_dirty(struct folio *folio, struct address_space *mapping,
                 int warn)
{
    unsigned long flags;

    xa_lock_irqsave(&mapping->i_pages, flags);
    if (folio->mapping) {   /* Race with truncate? */
        WARN_ON_ONCE(warn && !folio_test_uptodate(folio));
        folio_account_dirtied(folio, mapping);
        __xa_set_mark(&mapping->i_pages, folio_index(folio),
                PAGECACHE_TAG_DIRTY);
    }
    xa_unlock_irqrestore(&mapping->i_pages, flags);
}
