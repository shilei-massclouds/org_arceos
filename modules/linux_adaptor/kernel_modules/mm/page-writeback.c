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
 * The longest time for which data is allowed to remain dirty
 */
unsigned int dirty_expire_interval = 30 * 100; /* centiseconds */

struct wb_domain global_wb_domain;

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
    pr_notice("%s: No impl.", __func__);
    PANIC("");
}

static pgoff_t wbc_end(struct writeback_control *wbc)
{
    if (wbc->range_cyclic)
        return -1;
    return wbc->range_end >> PAGE_SHIFT;
}

static xa_mark_t wbc_to_tag(struct writeback_control *wbc)
{
    if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
        return PAGECACHE_TAG_TOWRITE;
    return PAGECACHE_TAG_DIRTY;
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
    pr_notice("%s: No impl.", __func__);
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
    pr_notice("%s: No impl.", __func__);
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
    pr_notice("%s: No impl.", __func__);
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
    pr_notice("%s: No impl.", __func__);
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
    pr_notice("%s: No impl.", __func__);
}

int do_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
    int ret;
    struct bdi_writeback *wb;

    pr_debug("%s: nr_to_write(%lx)\n", __func__, wbc->nr_to_write);
    if (wbc->nr_to_write <= 0)
        return 0;
    wb = inode_to_wb_wbc(mapping->host, wbc);
    wb_bandwidth_estimate_start(wb);
    while (1) {
        if (mapping->a_ops->writepages) {
            ret = mapping->a_ops->writepages(mapping, wbc);
        } else if (mapping->a_ops->writepage) {
            ret = writeback_use_writepage(mapping, wbc);
        } else {
            /* deal with chardevs and other special files */
            ret = 0;
        }
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

    pr_debug("%s: (%lx,%lx)", __func__, start, end);
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

    pr_debug("%s: keep_write(%d)", __func__, keep_write);
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
    pr_notice("%s: No impl.", __func__);
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

static bool folio_prepare_writeback(struct address_space *mapping,
        struct writeback_control *wbc, struct folio *folio)
{
    /*
     * Folio truncated or invalidated. We can freely skip it then,
     * even for data integrity operations: the folio has disappeared
     * concurrently, so there could be no real expectation of this
     * data integrity operation even if there is now a new, dirty
     * folio at the same pagecache index.
     */
    if (unlikely(folio->mapping != mapping))
        return false;

    /*
     * Did somebody else write it for us?
     */
    if (!folio_test_dirty(folio))
        return false;

    if (folio_test_writeback(folio)) {
        if (wbc->sync_mode == WB_SYNC_NONE)
            return false;
        folio_wait_writeback(folio);
    }
    BUG_ON(folio_test_writeback(folio));

    if (!folio_clear_dirty_for_io(folio))
        return false;

    return true;
}

static struct folio *writeback_get_folio(struct address_space *mapping,
        struct writeback_control *wbc)
{
    struct folio *folio;

retry:
    folio = folio_batch_next(&wbc->fbatch);
    if (!folio) {
        folio_batch_release(&wbc->fbatch);
        cond_resched();
        filemap_get_folios_tag(mapping, &wbc->index, wbc_end(wbc),
                wbc_to_tag(wbc), &wbc->fbatch);
        folio = folio_batch_next(&wbc->fbatch);
        if (!folio)
            return NULL;
    }

    folio_lock(folio);
    if (unlikely(!folio_prepare_writeback(mapping, wbc, folio))) {
        folio_unlock(folio);
        goto retry;
    }

    trace_wbc_writepage(wbc, inode_to_bdi(mapping->host));
    return folio;
}

/**
 * writeback_iter - iterate folio of a mapping for writeback
 * @mapping: address space structure to write
 * @wbc: writeback context
 * @folio: previously iterated folio (%NULL to start)
 * @error: in-out pointer for writeback errors (see below)
 *
 * This function returns the next folio for the writeback operation described by
 * @wbc on @mapping and  should be called in a while loop in the ->writepages
 * implementation.
 *
 * To start the writeback operation, %NULL is passed in the @folio argument, and
 * for every subsequent iteration the folio returned previously should be passed
 * back in.
 *
 * If there was an error in the per-folio writeback inside the writeback_iter()
 * loop, @error should be set to the error value.
 *
 * Once the writeback described in @wbc has finished, this function will return
 * %NULL and if there was an error in any iteration restore it to @error.
 *
 * Note: callers should not manually break out of the loop using break or goto
 * but must keep calling writeback_iter() until it returns %NULL.
 *
 * Return: the folio to write or %NULL if the loop is done.
 */
struct folio *writeback_iter(struct address_space *mapping,
        struct writeback_control *wbc, struct folio *folio, int *error)
{
    if (!folio) {
        folio_batch_init(&wbc->fbatch);
        wbc->saved_err = *error = 0;

        /*
         * For range cyclic writeback we remember where we stopped so
         * that we can continue where we stopped.
         *
         * For non-cyclic writeback we always start at the beginning of
         * the passed in range.
         */
        if (wbc->range_cyclic)
            wbc->index = mapping->writeback_index;
        else
            wbc->index = wbc->range_start >> PAGE_SHIFT;

        /*
         * To avoid livelocks when other processes dirty new pages, we
         * first tag pages which should be written back and only then
         * start writing them.
         *
         * For data-integrity writeback we have to be careful so that we
         * do not miss some pages (e.g., because some other process has
         * cleared the TOWRITE tag we set).  The rule we follow is that
         * TOWRITE tag can be cleared only by the process clearing the
         * DIRTY tag (and submitting the page for I/O).
         */
        if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
            tag_pages_for_writeback(mapping, wbc->index,
                    wbc_end(wbc));
    } else {
        wbc->nr_to_write -= folio_nr_pages(folio);

        WARN_ON_ONCE(*error > 0);

        /*
         * For integrity writeback we have to keep going until we have
         * written all the folios we tagged for writeback above, even if
         * we run past wbc->nr_to_write or encounter errors.
         * We stash away the first error we encounter in wbc->saved_err
         * so that it can be retrieved when we're done.  This is because
         * the file system may still have state to clear for each folio.
         *
         * For background writeback we exit as soon as we run past
         * wbc->nr_to_write or encounter the first error.
         */
        if (wbc->sync_mode == WB_SYNC_ALL) {
            if (*error && !wbc->saved_err)
                wbc->saved_err = *error;
        } else {
            if (*error || wbc->nr_to_write <= 0)
                goto done;
        }
    }

    folio = writeback_get_folio(mapping, wbc);
    if (!folio) {
        /*
         * To avoid deadlocks between range_cyclic writeback and callers
         * that hold pages in PageWriteback to aggregate I/O until
         * the writeback iteration finishes, we do not loop back to the
         * start of the file.  Doing so causes a page lock/page
         * writeback access order inversion - we should only ever lock
         * multiple pages in ascending page->index order, and looping
         * back to the start of the file violates that rule and causes
         * deadlocks.
         */
        if (wbc->range_cyclic)
            mapping->writeback_index = 0;

        /*
         * Return the first error we encountered (if there was any) to
         * the caller.
         */
        *error = wbc->saved_err;
    }
    return folio;

done:
    if (wbc->range_cyclic)
        mapping->writeback_index = folio_next_index(folio);
    folio_batch_release(&wbc->fbatch);
    return NULL;
}


/**
 * write_cache_pages - walk the list of dirty pages of the given address space and write all of them.
 * @mapping: address space structure to write
 * @wbc: subtract the number of written pages from *@wbc->nr_to_write
 * @writepage: function called for each page
 * @data: data passed to writepage function
 *
 * Return: %0 on success, negative error code otherwise
 *
 * Note: please use writeback_iter() instead.
 */
int write_cache_pages(struct address_space *mapping,
              struct writeback_control *wbc, writepage_t writepage,
              void *data)
{
    struct folio *folio = NULL;
    int error;

    while ((folio = writeback_iter(mapping, wbc, folio, &error))) {
        error = writepage(folio, wbc, data);
        if (error == AOP_WRITEPAGE_ACTIVATE) {
            folio_unlock(folio);
            error = 0;
        }
    }

    return error;
}

/*
 * This cancels just the dirty bit on the kernel page itself, it does NOT
 * actually remove dirty bits on any mmap's that may be around. It also
 * leaves the page tagged dirty, so any sync activity will still find it on
 * the dirty lists, and in particular, clear_page_dirty_for_io() will still
 * look at the dirty bits in the VM.
 *
 * Doing this should *normally* only ever be done when a page is truncated,
 * and is not actually mapped anywhere at all. However, fs/buffer.c does
 * this when it notices that somebody has cleaned out all the buffers on a
 * page without actually doing it through the VM. Can you say "ext3 is
 * horribly ugly"? Thought you could.
 */
void __folio_cancel_dirty(struct folio *folio)
{
    struct address_space *mapping = folio_mapping(folio);

    if (mapping_can_writeback(mapping)) {
        struct inode *inode = mapping->host;
        struct bdi_writeback *wb;
        struct wb_lock_cookie cookie = {};

        folio_memcg_lock(folio);
        wb = unlocked_inode_to_wb_begin(inode, &cookie);

        if (folio_test_clear_dirty(folio))
            folio_account_cleaned(folio, wb);

        unlocked_inode_to_wb_end(inode, &cookie);
        folio_memcg_unlock(folio);
    } else {
        folio_clear_dirty(folio);
    }
}

/*
 * Helper function for deaccounting dirty page without writeback.
 *
 * Caller must hold folio_memcg_lock().
 */
void folio_account_cleaned(struct folio *folio, struct bdi_writeback *wb)
{
    long nr = folio_nr_pages(folio);

#if 0
    lruvec_stat_mod_folio(folio, NR_FILE_DIRTY, -nr);
    zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, -nr);
#endif
    wb_stat_mod(wb, WB_RECLAIMABLE, -nr);
    task_io_account_cancelled_write(nr * PAGE_SIZE);
}

/**
 * wb_over_bg_thresh - does @wb need to be written back?
 * @wb: bdi_writeback of interest
 *
 * Determines whether background writeback should keep writing @wb or it's
 * clean enough.
 *
 * Return: %true if writeback should continue.
 */
bool wb_over_bg_thresh(struct bdi_writeback *wb)
{
#if 0
    struct dirty_throttle_control gdtc = { GDTC_INIT(wb) };
    struct dirty_throttle_control mdtc = { MDTC_INIT(wb, &gdtc) };

    if (domain_over_bg_thresh(&gdtc))
        return true;

    if (mdtc_valid(&mdtc))
        return domain_over_bg_thresh(&mdtc);
#endif
    pr_notice("%s: No impl.", __func__);

    return false;
}
