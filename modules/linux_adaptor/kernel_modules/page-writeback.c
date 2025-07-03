#include <linux/mm.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/buffer_head.h>

#include "booter.h"

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
    log_error("%s: No impl.\n", __func__);
    return 0;
}

int test_clear_page_writeback(struct page *page)
{
    log_error("%s: No impl.\n", __func__);
    return 0;
}
