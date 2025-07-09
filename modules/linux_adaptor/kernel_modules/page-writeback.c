#include <linux/mm.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/buffer_head.h>
#include <linux/pagevec.h>

#include "booter.h"

/*
 * The interval between `kupdate'-style writebacks
 */
unsigned int dirty_writeback_interval = 5 * 100; /* centiseconds */

/*
 * The longest time for which data is allowed to remain dirty
 */
unsigned int dirty_expire_interval = 30 * 100; /* centiseconds */

struct wb_domain global_wb_domain;

/**
 * wait_for_stable_page() - wait for writeback to finish, if necessary.
 * @page:   The page to wait on.
 *
 * This function determines if the given page is related to a backing device
 * that requires page contents to be held stable during writeback.  If so, then
 * it will wait for any pending writeback to complete.
 */
void wait_for_stable_page(struct page *page)
{
    log_error("%s: No impl.\n", __func__);
}

/**
 * balance_dirty_pages_ratelimited - balance dirty memory state
 * @mapping: address_space which was dirtied
 *
 * Processes which are dirtying memory should call in here once for each page
 * which was newly dirtied.  The function will periodically check the system's
 * dirty state and will initiate writeback if needed.
 *
 * On really big machines, get_writeback_state is expensive, so try to avoid
 * calling it too often (ratelimiting).  But once we're over the dirty memory
 * limit we decrease the ratelimiting by a lot, to prevent individual processes
 * from overshooting the limit by (ratelimit_pages) each.
 */
void balance_dirty_pages_ratelimited(struct address_space *mapping)
{
    log_error("%s: No impl.\n", __func__);
}

int do_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	int ret;

	if (wbc->nr_to_write <= 0)
		return 0;
	while (1) {
		if (mapping->a_ops->writepages)
			ret = mapping->a_ops->writepages(mapping, wbc);
		else
			ret = generic_writepages(mapping, wbc);
		if ((ret != -ENOMEM) || (wbc->sync_mode != WB_SYNC_ALL))
			break;
		cond_resched();
		congestion_wait(BLK_RW_ASYNC, HZ/50);
	}
	return ret;
}

/**
 * tag_pages_for_writeback - tag pages to be written by write_cache_pages
 * @mapping: address space structure to write
 * @start: starting page index
 * @end: ending page index (inclusive)
 *
 * This function scans the page range from @start to @end (inclusive) and tags
 * all pages that have DIRTY tag set with a special TOWRITE tag. The idea is
 * that write_cache_pages (or whoever calls this function) will then use
 * TOWRITE tag to identify pages eligible for writeback.  This mechanism is
 * used to avoid livelocking of writeback by a process steadily creating new
 * dirty pages in the file (thus it is important for this function to be quick
 * so that it can tag pages faster than a dirtying process can create them).
 */
void tag_pages_for_writeback(struct address_space *mapping,
                 pgoff_t start, pgoff_t end)
{
    XA_STATE(xas, &mapping->i_pages, start);
    unsigned int tagged = 0;
    void *page;

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

/*
 * Wait for a page to complete writeback
 */
void wait_on_page_writeback(struct page *page)
{
    log_error("%s: ...\n", __func__);
    if (PageWriteback(page)) {
        //trace_wait_on_page_writeback(page, page_mapping(page));
        wait_on_page_bit(page, PG_writeback);
    }
}

/*
 * Clear a page's dirty flag, while caring for dirty memory accounting.
 * Returns true if the page was previously dirty.
 *
 * This is for preparing to put the page under writeout.  We leave the page
 * tagged as dirty in the xarray so that a concurrent write-for-sync
 * can discover it via a PAGECACHE_TAG_DIRTY walk.  The ->writepage
 * implementation will run either set_page_writeback() or set_page_dirty(),
 * at which stage we bring the page's dirty flag and xarray dirty tag
 * back into sync.
 *
 * This incoherency between the page's dirty flag and xarray tag is
 * unfortunate, but it only exists while the page is locked.
 */
int clear_page_dirty_for_io(struct page *page)
{
    struct address_space *mapping = page_mapping(page);
    int ret = 0;

    VM_BUG_ON_PAGE(!PageLocked(page), page);

    if (mapping && mapping_cap_account_dirty(mapping)) {
        struct inode *inode = mapping->host;
        struct bdi_writeback *wb;
        struct wb_lock_cookie cookie = {};

        /*
         * Yes, Virginia, this is indeed insane.
         *
         * We use this sequence to make sure that
         *  (a) we account for dirty stats properly
         *  (b) we tell the low-level filesystem to
         *      mark the whole page dirty if it was
         *      dirty in a pagetable. Only to then
         *  (c) clean the page again and return 1 to
         *      cause the writeback.
         *
         * This way we avoid all nasty races with the
         * dirty bit in multiple places and clearing
         * them concurrently from different threads.
         *
         * Note! Normally the "set_page_dirty(page)"
         * has no effect on the actual dirty bit - since
         * that will already usually be set. But we
         * need the side effects, and it can help us
         * avoid races.
         *
         * We basically use the page "master dirty bit"
         * as a serialization point for all the different
         * threads doing their things.
         */
        if (page_mkclean(page))
            set_page_dirty(page);
        /*
         * We carefully synchronise fault handlers against
         * installing a dirty pte and marking the page dirty
         * at this point.  We do this by having them hold the
         * page lock while dirtying the page, and pages are
         * always locked coming in here, so we get the desired
         * exclusion.
         */
        wb = unlocked_inode_to_wb_begin(inode, &cookie);
        if (TestClearPageDirty(page)) {
            //dec_lruvec_page_state(page, NR_FILE_DIRTY);
            //dec_zone_page_state(page, NR_ZONE_WRITE_PENDING);
            dec_wb_stat(wb, WB_RECLAIMABLE);
            ret = 1;
        }
        unlocked_inode_to_wb_end(inode, &cookie);
        return ret;
    }
    return TestClearPageDirty(page);
}

/*
 * Dirty a page.
 *
 * For pages with a mapping this should be done under the page lock
 * for the benefit of asynchronous memory errors who prefer a consistent
 * dirty state. This rule can be broken in some special cases,
 * but should be better not to.
 *
 * If the mapping doesn't provide a set_page_dirty a_op, then
 * just fall through and assume that it wants buffer_heads.
 */
int set_page_dirty(struct page *page)
{
    struct address_space *mapping = page_mapping(page);

    page = compound_head(page);
    if (likely(mapping)) {
        int (*spd)(struct page *) = mapping->a_ops->set_page_dirty;
        /*
         * readahead/lru_deactivate_page could remain
         * PG_readahead/PG_reclaim due to race with end_page_writeback
         * About readahead, if the page is written, the flags would be
         * reset. So no problem.
         * About lru_deactivate_page, if the page is redirty, the flag
         * will be reset. So no problem. but if the page is used by readahead
         * it will confuse readahead and make it restart the size rampup
         * process. But it's a trivial problem.
         */
        if (PageReclaim(page))
            ClearPageReclaim(page);
#ifdef CONFIG_BLOCK
        if (!spd)
            spd = __set_page_dirty_buffers;
#endif
        return (*spd)(page);
    }
    if (!PageDirty(page)) {
        if (!TestSetPageDirty(page))
            return 1;
    }
    return 0;
}

int __test_set_page_writeback(struct page *page, bool keep_write)
{
    struct address_space *mapping = page_mapping(page);
    int ret, access_ret;

    lock_page_memcg(page);
    if (mapping && mapping_use_writeback_tags(mapping)) {
        XA_STATE(xas, &mapping->i_pages, page_index(page));
        struct inode *inode = mapping->host;
        struct backing_dev_info *bdi = inode_to_bdi(inode);
        unsigned long flags;

        xas_lock_irqsave(&xas, flags);
        xas_load(&xas);
        ret = TestSetPageWriteback(page);
        if (!ret) {
            bool on_wblist;

            on_wblist = mapping_tagged(mapping,
                           PAGECACHE_TAG_WRITEBACK);

            xas_set_mark(&xas, PAGECACHE_TAG_WRITEBACK);
            if (bdi_cap_account_writeback(bdi))
                inc_wb_stat(inode_to_wb(inode), WB_WRITEBACK);

            /*
             * We can come through here when swapping anonymous
             * pages, so we don't necessarily have an inode to track
             * for sync.
             */
            if (mapping->host && !on_wblist)
                sb_mark_inode_writeback(mapping->host);
        }
        if (!PageDirty(page))
            xas_clear_mark(&xas, PAGECACHE_TAG_DIRTY);
        if (!keep_write)
            xas_clear_mark(&xas, PAGECACHE_TAG_TOWRITE);
        xas_unlock_irqrestore(&xas, flags);
    } else {
        ret = TestSetPageWriteback(page);
    }
    /*
    if (!ret) {
        inc_lruvec_page_state(page, NR_WRITEBACK);
        inc_zone_page_state(page, NR_ZONE_WRITE_PENDING);
    }
    */
    unlock_page_memcg(page);
    access_ret = arch_make_page_accessible(page);
    /*
     * If writeback has been triggered on a page that cannot be made
     * accessible, it is too late to recover here.
     */
    VM_BUG_ON_PAGE(access_ret != 0, page);

    return ret;
}

/*
 * mark an inode as under writeback on the sb
 */
void sb_mark_inode_writeback(struct inode *inode)
{
    log_error("%s: No impl.\n", __func__);
}

/*
 * Increment @wb's writeout completion count and the global writeout
 * completion count. Called from test_clear_page_writeback().
 */
static inline void __wb_writeout_inc(struct bdi_writeback *wb)
{
    log_error("%s: No impl.\n", __func__);
}

int test_clear_page_writeback(struct page *page)
{
    struct address_space *mapping = page_mapping(page);
    struct mem_cgroup *memcg;
    struct lruvec *lruvec;
    int ret;

    memcg = lock_page_memcg(page);
    lruvec = mem_cgroup_page_lruvec(page, page_pgdat(page));
    if (mapping && mapping_use_writeback_tags(mapping)) {
        struct inode *inode = mapping->host;
        struct backing_dev_info *bdi = inode_to_bdi(inode);
        unsigned long flags;

        xa_lock_irqsave(&mapping->i_pages, flags);
        ret = TestClearPageWriteback(page);
        if (ret) {
            __xa_clear_mark(&mapping->i_pages, page_index(page),
                        PAGECACHE_TAG_WRITEBACK);
            if (bdi_cap_account_writeback(bdi)) {
                struct bdi_writeback *wb = inode_to_wb(inode);

                dec_wb_stat(wb, WB_WRITEBACK);
                __wb_writeout_inc(wb);
            }
        }

        if (mapping->host && !mapping_tagged(mapping,
                             PAGECACHE_TAG_WRITEBACK))
            sb_clear_inode_writeback(mapping->host);

        xa_unlock_irqrestore(&mapping->i_pages, flags);
    } else {
        ret = TestClearPageWriteback(page);
    }
    /*
     * NOTE: Page might be free now! Writeback doesn't hold a page
     * reference on its own, it relies on truncation to wait for
     * the clearing of PG_writeback. The below can only access
     * page state that is static across allocation cycles.
     */
    /*
    if (ret) {
        dec_lruvec_state(lruvec, NR_WRITEBACK);
        dec_zone_page_state(page, NR_ZONE_WRITE_PENDING);
        inc_node_page_state(page, NR_WRITTEN);
    }
    */
    __unlock_page_memcg(memcg);
    return ret;
}

/*
 * clear an inode as under writeback on the sb
 */
void sb_clear_inode_writeback(struct inode *inode)
{
    log_error("%s: No impl.\n", __func__);
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
    log_error("%s: No impl.\n", __func__);
    return false;
}

void wb_update_bandwidth(struct bdi_writeback *wb, unsigned long start_time)
{
    log_error("%s: No impl.\n", __func__);
}

/*
 * Function used by generic_writepages to call the real writepage
 * function and set the mapping flags on error
 */
static int __writepage(struct page *page, struct writeback_control *wbc,
               void *data)
{
    struct address_space *mapping = data;
    int ret = mapping->a_ops->writepage(page, wbc);
    mapping_set_error(mapping, ret);
    return ret;
}

/**
 * generic_writepages - walk the list of dirty pages of the given address space and writepage() all of them.
 * @mapping: address space structure to write
 * @wbc: subtract the number of written pages from *@wbc->nr_to_write
 *
 * This is a library function, which implements the writepages()
 * address_space_operation.
 *
 * Return: %0 on success, negative error code otherwise
 */
int generic_writepages(struct address_space *mapping,
               struct writeback_control *wbc)
{
    struct blk_plug plug;
    int ret;

    /* deal with chardevs and other special file */
    if (!mapping->a_ops->writepage)
        return 0;

    blk_start_plug(&plug);
    ret = write_cache_pages(mapping, wbc, __writepage, mapping);
    blk_finish_plug(&plug);
    return ret;
}

/**
 * write_cache_pages - walk the list of dirty pages of the given address space and write all of them.
 * @mapping: address space structure to write
 * @wbc: subtract the number of written pages from *@wbc->nr_to_write
 * @writepage: function called for each page
 * @data: data passed to writepage function
 *
 * If a page is already under I/O, write_cache_pages() skips it, even
 * if it's dirty.  This is desirable behaviour for memory-cleaning writeback,
 * but it is INCORRECT for data-integrity system calls such as fsync().  fsync()
 * and msync() need to guarantee that all the data which was dirty at the time
 * the call was made get new I/O started against them.  If wbc->sync_mode is
 * WB_SYNC_ALL then we were called for data integrity and we must wait for
 * existing IO to complete.
 *
 * To avoid livelocks (when other process dirties new pages), we first tag
 * pages which should be written back with TOWRITE tag and only then start
 * writing them. For data-integrity sync we have to be careful so that we do
 * not miss some pages (e.g., because some other process has cleared TOWRITE
 * tag we set). The rule we follow is that TOWRITE tag can be cleared only
 * by the process clearing the DIRTY tag (and submitting the page for IO).
 *
 * To avoid deadlocks between range_cyclic writeback and callers that hold
 * pages in PageWriteback to aggregate IO until write_cache_pages() returns,
 * we do not loop back to the start of the file. Doing so causes a page
 * lock/page writeback access order inversion - we should only ever lock
 * multiple pages in ascending page->index order, and looping back to the start
 * of the file violates that rule and causes deadlocks.
 *
 * Return: %0 on success, negative error code otherwise
 */
int write_cache_pages(struct address_space *mapping,
              struct writeback_control *wbc, writepage_t writepage,
              void *data)
{
    int ret = 0;
    int done = 0;
    int error;
    struct pagevec pvec;
    int nr_pages;
    pgoff_t index;
    pgoff_t end;        /* Inclusive */
    pgoff_t done_index;
    int range_whole = 0;
    xa_mark_t tag;

    pagevec_init(&pvec);
    if (wbc->range_cyclic) {
        index = mapping->writeback_index; /* prev offset */
        end = -1;
    } else {
        index = wbc->range_start >> PAGE_SHIFT;
        end = wbc->range_end >> PAGE_SHIFT;
        if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
            range_whole = 1;
    }
    if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages) {
        tag_pages_for_writeback(mapping, index, end);
        tag = PAGECACHE_TAG_TOWRITE;
    } else {
        tag = PAGECACHE_TAG_DIRTY;
    }
    done_index = index;
    while (!done && (index <= end)) {
        int i;

        nr_pages = pagevec_lookup_range_tag(&pvec, mapping, &index, end,
                tag);
        if (nr_pages == 0)
            break;

        for (i = 0; i < nr_pages; i++) {
            struct page *page = pvec.pages[i];

            done_index = page->index;

            lock_page(page);

            /*
             * Page truncated or invalidated. We can freely skip it
             * then, even for data integrity operations: the page
             * has disappeared concurrently, so there could be no
             * real expectation of this data interity operation
             * even if there is now a new, dirty page at the same
             * pagecache address.
             */
            if (unlikely(page->mapping != mapping)) {
continue_unlock:
                unlock_page(page);
                continue;
            }

            if (!PageDirty(page)) {
                /* someone wrote it for us */
                goto continue_unlock;
            }

            if (PageWriteback(page)) {
                if (wbc->sync_mode != WB_SYNC_NONE)
                    wait_on_page_writeback(page);
                else
                    goto continue_unlock;
            }

            BUG_ON(PageWriteback(page));
            if (!clear_page_dirty_for_io(page))
                goto continue_unlock;

            //trace_wbc_writepage(wbc, inode_to_bdi(mapping->host));
            error = (*writepage)(page, wbc, data);
            if (unlikely(error)) {
                /*
                 * Handle errors according to the type of
                 * writeback. There's no need to continue for
                 * background writeback. Just push done_index
                 * past this page so media errors won't choke
                 * writeout for the entire file. For integrity
                 * writeback, we must process the entire dirty
                 * set regardless of errors because the fs may
                 * still have state to clear for each page. In
                 * that case we continue processing and return
                 * the first error.
                 */
                if (error == AOP_WRITEPAGE_ACTIVATE) {
                    unlock_page(page);
                    error = 0;
                } else if (wbc->sync_mode != WB_SYNC_ALL) {
                    ret = error;
                    done_index = page->index + 1;
                    done = 1;
                    break;
                }
                if (!ret)
                    ret = error;
            }

            /*
             * We stop writing back only if we are not doing
             * integrity sync. In case of integrity sync we have to
             * keep going until we have written all the pages
             * we tagged for writeback prior to entering this loop.
             */
            if (--wbc->nr_to_write <= 0 &&
                wbc->sync_mode == WB_SYNC_NONE) {
                done = 1;
                break;
            }
        }
        pagevec_release(&pvec);
        cond_resched();
    }

    /*
     * If we hit the last page and there is more work to be done: wrap
     * back the index back to the start of the file for the next
     * time we are called.
     */
    if (wbc->range_cyclic && !done)
        done_index = 0;
    if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
        mapping->writeback_index = done_index;

    return ret;
}
