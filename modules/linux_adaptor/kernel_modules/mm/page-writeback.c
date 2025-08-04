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

#include "../adaptor.h"

/*
 * Estimate write bandwidth at 200ms intervals.
 */
#define BANDWIDTH_INTERVAL  max(HZ/5, 1)

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

static void wb_bandwidth_estimate_start(struct bdi_writeback *wb)
{
    pr_err("%s: No impl.", __func__);
}

static int writeback_use_writepage(struct address_space *mapping,
        struct writeback_control *wbc)
{
    PANIC("");
}

void wb_update_bandwidth(struct bdi_writeback *wb)
{
#if 0
    struct dirty_throttle_control gdtc = { GDTC_INIT(wb) };

    __wb_update_bandwidth(&gdtc, NULL, false);
#endif
    pr_err("%s: No impl.", __func__);
}

int do_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
    int ret;
    struct bdi_writeback *wb;

    printk("%s: nr_to_write(%lx)\n", __func__, wbc->nr_to_write);
    if (wbc->nr_to_write <= 0)
        return 0;
    wb = inode_to_wb_wbc(mapping->host, wbc);
    wb_bandwidth_estimate_start(wb);
    while (1) {
        printk("%s: step1\n", __func__);
        if (mapping->a_ops->writepages) {
            ret = mapping->a_ops->writepages(mapping, wbc);
        } else if (mapping->a_ops->writepage) {
            ret = writeback_use_writepage(mapping, wbc);
        } else {
            /* deal with chardevs and other special files */
            ret = 0;
        }
        printk("%s: step2\n", __func__);
        if (ret != -ENOMEM || wbc->sync_mode != WB_SYNC_ALL)
            break;

        /*
         * Lacking an allocation context or the locality or writeback
         * state of any of the inode's pages, throttle based on
         * writeback activity on the local node. It's as good a
         * guess as any.
         */
#if 0
        reclaim_throttle(NODE_DATA(numa_node_id()),
            VMSCAN_THROTTLE_WRITEBACK);
#endif
    }
    /*
     * Usually few pages are written by now from those we've just submitted
     * but if there's constant writeback being submitted, this makes sure
     * writeback bandwidth is updated once in a while.
     */
    if (time_is_before_jiffies(READ_ONCE(wb->bw_time_stamp) +
                   BANDWIDTH_INTERVAL))
        wb_update_bandwidth(wb);
    return ret;
}

/**
 * tag_pages_for_writeback - tag pages to be written by writeback
 * @mapping: address space structure to write
 * @start: starting page index
 * @end: ending page index (inclusive)
 *
 * This function scans the page range from @start to @end (inclusive) and tags
 * all pages that have DIRTY tag set with a special TOWRITE tag.  The caller
 * can then use the TOWRITE tag to identify pages eligible for writeback.
 * This mechanism is used to avoid livelocking of writeback by a process
 * steadily creating new dirty pages in the file (thus it is important for this
 * function to be quick so that it can tag pages faster than a dirtying process
 * can create them).
 */
void tag_pages_for_writeback(struct address_space *mapping,
                 pgoff_t start, pgoff_t end)
{
    XA_STATE(xas, &mapping->i_pages, start);
    unsigned int tagged = 0;
    void *page;

    printk("%s: step1 (%lx,%lx)\n", __func__, start, end);
    xas_lock_irq(&xas);
    xas_for_each_marked(&xas, page, end, PAGECACHE_TAG_DIRTY) {
        xas_set_mark(&xas, PAGECACHE_TAG_TOWRITE);
        if (++tagged % XA_CHECK_SCHED)
            continue;

        xas_pause(&xas);
        xas_unlock_irq(&xas);
        cond_resched();
        xas_lock_irq(&xas);
    }
    xas_unlock_irq(&xas);
}

/**
 * folio_wait_writeback - Wait for a folio to finish writeback.
 * @folio: The folio to wait for.
 *
 * If the folio is currently being written back to storage, wait for the
 * I/O to complete.
 *
 * Context: Sleeps.  Must be called in process context and with
 * no spinlocks held.  Caller should hold a reference on the folio.
 * If the folio is not locked, writeback may start again after writeback
 * has finished.
 */
void folio_wait_writeback(struct folio *folio)
{
    while (folio_test_writeback(folio)) {
        trace_folio_wait_writeback(folio, folio_mapping(folio));
        folio_wait_bit(folio, PG_writeback);
    }
}

/*
 * Clear a folio's dirty flag, while caring for dirty memory accounting.
 * Returns true if the folio was previously dirty.
 *
 * This is for preparing to put the folio under writeout.  We leave
 * the folio tagged as dirty in the xarray so that a concurrent
 * write-for-sync can discover it via a PAGECACHE_TAG_DIRTY walk.
 * The ->writepage implementation will run either folio_start_writeback()
 * or folio_mark_dirty(), at which stage we bring the folio's dirty flag
 * and xarray dirty tag back into sync.
 *
 * This incoherency between the folio's dirty flag and xarray tag is
 * unfortunate, but it only exists while the folio is locked.
 */
bool folio_clear_dirty_for_io(struct folio *folio)
{
    struct address_space *mapping = folio_mapping(folio);
    bool ret = false;

    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

    if (mapping && mapping_can_writeback(mapping)) {
        struct inode *inode = mapping->host;
        struct bdi_writeback *wb;
        struct wb_lock_cookie cookie = {};

        /*
         * Yes, Virginia, this is indeed insane.
         *
         * We use this sequence to make sure that
         *  (a) we account for dirty stats properly
         *  (b) we tell the low-level filesystem to
         *      mark the whole folio dirty if it was
         *      dirty in a pagetable. Only to then
         *  (c) clean the folio again and return 1 to
         *      cause the writeback.
         *
         * This way we avoid all nasty races with the
         * dirty bit in multiple places and clearing
         * them concurrently from different threads.
         *
         * Note! Normally the "folio_mark_dirty(folio)"
         * has no effect on the actual dirty bit - since
         * that will already usually be set. But we
         * need the side effects, and it can help us
         * avoid races.
         *
         * We basically use the folio "master dirty bit"
         * as a serialization point for all the different
         * threads doing their things.
         */
        if (folio_mkclean(folio))
            folio_mark_dirty(folio);
        /*
         * We carefully synchronise fault handlers against
         * installing a dirty pte and marking the folio dirty
         * at this point.  We do this by having them hold the
         * page lock while dirtying the folio, and folios are
         * always locked coming in here, so we get the desired
         * exclusion.
         */
        wb = unlocked_inode_to_wb_begin(inode, &cookie);
        if (folio_test_clear_dirty(folio)) {
            long nr = folio_nr_pages(folio);
            //lruvec_stat_mod_folio(folio, NR_FILE_DIRTY, -nr);
            //zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, -nr);
            wb_stat_mod(wb, WB_RECLAIMABLE, -nr);
            ret = true;
        }
        unlocked_inode_to_wb_end(inode, &cookie);
        return ret;
    }
    PANIC("");
    return folio_test_clear_dirty(folio);
}

static void wb_inode_writeback_start(struct bdi_writeback *wb)
{
    atomic_inc(&wb->writeback_inodes);
}

void __folio_start_writeback(struct folio *folio, bool keep_write)
{
    long nr = folio_nr_pages(folio);
    struct address_space *mapping = folio_mapping(folio);
    int access_ret;

    printk("%s: step1 keep_write(%d)\n", __func__, keep_write);
    VM_BUG_ON_FOLIO(folio_test_writeback(folio), folio);

    folio_memcg_lock(folio);
    if (mapping && mapping_use_writeback_tags(mapping)) {
        XA_STATE(xas, &mapping->i_pages, folio_index(folio));
        struct inode *inode = mapping->host;
        struct backing_dev_info *bdi = inode_to_bdi(inode);
        unsigned long flags;
        bool on_wblist;

        xas_lock_irqsave(&xas, flags);
        xas_load(&xas);
        folio_test_set_writeback(folio);

        on_wblist = mapping_tagged(mapping, PAGECACHE_TAG_WRITEBACK);

        xas_set_mark(&xas, PAGECACHE_TAG_WRITEBACK);
        if (bdi->capabilities & BDI_CAP_WRITEBACK_ACCT) {
            struct bdi_writeback *wb = inode_to_wb(inode);

            wb_stat_mod(wb, WB_WRITEBACK, nr);
            if (!on_wblist)
                wb_inode_writeback_start(wb);
        }

        /*
         * We can come through here when swapping anonymous
         * folios, so we don't necessarily have an inode to
         * track for sync.
         */
        if (mapping->host && !on_wblist)
            sb_mark_inode_writeback(mapping->host);
        if (!folio_test_dirty(folio))
            xas_clear_mark(&xas, PAGECACHE_TAG_DIRTY);
        if (!keep_write)
            xas_clear_mark(&xas, PAGECACHE_TAG_TOWRITE);
        xas_unlock_irqrestore(&xas, flags);
    } else {
        folio_test_set_writeback(folio);
    }

    //lruvec_stat_mod_folio(folio, NR_WRITEBACK, nr);
    //zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, nr);
    folio_memcg_unlock(folio);

    access_ret = arch_make_folio_accessible(folio);
    /*
     * If writeback has been triggered on a page that cannot be made
     * accessible, it is too late to recover here.
     */
    VM_BUG_ON_FOLIO(access_ret != 0, folio);
}

/*
 * Increment @wb's writeout completion count and the global writeout
 * completion count. Called from __folio_end_writeback().
 */
static inline void __wb_writeout_add(struct bdi_writeback *wb, long nr)
{
    pr_err("%s: No impl.", __func__);
#if 0
    struct wb_domain *cgdom;

    wb_stat_mod(wb, WB_WRITTEN, nr);
    wb_domain_writeout_add(&global_wb_domain, &wb->completions,
                   wb->bdi->max_prop_frac, nr);

    cgdom = mem_cgroup_wb_domain(wb);
    if (cgdom)
        wb_domain_writeout_add(cgdom, wb_memcg_completions(wb),
                       wb->bdi->max_prop_frac, nr);
#endif
}

static void wb_inode_writeback_end(struct bdi_writeback *wb)
{
    unsigned long flags;
    atomic_dec(&wb->writeback_inodes);
    /*
     * Make sure estimate of writeback throughput gets updated after
     * writeback completed. We delay the update by BANDWIDTH_INTERVAL
     * (which is the interval other bandwidth updates use for batching) so
     * that if multiple inodes end writeback at a similar time, they get
     * batched into one bandwidth update.
     */
    spin_lock_irqsave(&wb->work_lock, flags);
    if (test_bit(WB_registered, &wb->state))
        queue_delayed_work(bdi_wq, &wb->bw_dwork, BANDWIDTH_INTERVAL);
    spin_unlock_irqrestore(&wb->work_lock, flags);
}

bool __folio_end_writeback(struct folio *folio)
{
    long nr = folio_nr_pages(folio);
    struct address_space *mapping = folio_mapping(folio);
    bool ret;

    folio_memcg_lock(folio);
    if (mapping && mapping_use_writeback_tags(mapping)) {
        struct inode *inode = mapping->host;
        struct backing_dev_info *bdi = inode_to_bdi(inode);
        unsigned long flags;

        xa_lock_irqsave(&mapping->i_pages, flags);
        ret = folio_xor_flags_has_waiters(folio, 1 << PG_writeback);
        __xa_clear_mark(&mapping->i_pages, folio_index(folio),
                    PAGECACHE_TAG_WRITEBACK);
        if (bdi->capabilities & BDI_CAP_WRITEBACK_ACCT) {
            struct bdi_writeback *wb = inode_to_wb(inode);

            wb_stat_mod(wb, WB_WRITEBACK, -nr);
            __wb_writeout_add(wb, nr);
            if (!mapping_tagged(mapping, PAGECACHE_TAG_WRITEBACK))
                wb_inode_writeback_end(wb);
        }

        if (mapping->host && !mapping_tagged(mapping,
                             PAGECACHE_TAG_WRITEBACK))
            sb_clear_inode_writeback(mapping->host);

        xa_unlock_irqrestore(&mapping->i_pages, flags);
    } else {
        ret = folio_xor_flags_has_waiters(folio, 1 << PG_writeback);
    }

    //lruvec_stat_mod_folio(folio, NR_WRITEBACK, -nr);
    //zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, -nr);
    //node_stat_mod_folio(folio, NR_WRITTEN, nr);
    folio_memcg_unlock(folio);

    return ret;
}
