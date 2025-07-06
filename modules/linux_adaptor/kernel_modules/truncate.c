#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/cleancache.h>
#include <linux/buffer_head.h>
#include <linux/shmem_fs.h>

#include "booter.h"

/**
 * do_invalidatepage - invalidate part or all of a page
 * @page: the page which is affected
 * @offset: start of the range to invalidate
 * @length: length of the range to invalidate
 *
 * do_invalidatepage() is called when all or part of the page has become
 * invalidated by a truncate operation.
 *
 * do_invalidatepage() does not have to release all buffers, but it must
 * ensure that no dirty buffer is left outside @offset and that no I/O
 * is underway against any of the blocks which are outside the truncation
 * point.  Because the caller is about to free (and possibly reuse) those
 * blocks on-disk.
 */
void do_invalidatepage(struct page *page, unsigned int offset,
               unsigned int length)
{
    void (*invalidatepage)(struct page *, unsigned int, unsigned int);

    invalidatepage = page->mapping->a_ops->invalidatepage;
#ifdef CONFIG_BLOCK
    if (!invalidatepage)
        invalidatepage = block_invalidatepage;
#endif
    if (invalidatepage)
        (*invalidatepage)(page, offset, length);
}

/*
 * If truncate cannot remove the fs-private metadata from the page, the page
 * becomes orphaned.  It will be left on the LRU and may even be mapped into
 * user pagetables if we're racing with filemap_fault().
 *
 * We need to bale out if page->mapping is no longer equal to the original
 * mapping.  This happens a) when the VM reclaimed the page while we waited on
 * its lock, b) when a concurrent invalidate_mapping_pages got there first and
 * c) when tmpfs swizzles a page between a tmpfs inode and swapper_space.
 */
static void
truncate_cleanup_page(struct address_space *mapping, struct page *page)
{
    if (page_mapped(page)) {
        pgoff_t nr = PageTransHuge(page) ? HPAGE_PMD_NR : 1;
        unmap_mapping_pages(mapping, page->index, nr, false);
    }

    if (page_has_private(page))
        do_invalidatepage(page, 0, PAGE_SIZE);

    /*
     * Some filesystems seem to re-dirty the page even after
     * the VM has canceled the dirty bit (eg ext3 journaling).
     * Hence dirty accounting check is placed after invalidation.
     */
    cancel_dirty_page(page);
    ClearPageMappedToDisk(page);
}

/*
 * Unconditionally remove exceptional entries. Usually called from truncate
 * path. Note that the pagevec may be altered by this function by removing
 * exceptional entries similar to what pagevec_remove_exceptionals does.
 */
static void truncate_exceptional_pvec_entries(struct address_space *mapping,
                struct pagevec *pvec, pgoff_t *indices,
                pgoff_t end)
{
    int i, j;
    bool dax, lock;

    /* Handled by shmem itself */
    if (shmem_mapping(mapping))
        return;

    for (j = 0; j < pagevec_count(pvec); j++)
        if (xa_is_value(pvec->pages[j]))
            break;

    if (j == pagevec_count(pvec))
        return;

    dax = dax_mapping(mapping);
    lock = !dax && indices[j] < end;
    if (lock)
        xa_lock_irq(&mapping->i_pages);

    booter_panic("No impl.");
}

/**
 * truncate_inode_pages_range - truncate range of pages specified by start & end byte offsets
 * @mapping: mapping to truncate
 * @lstart: offset from which to truncate
 * @lend: offset to which to truncate (inclusive)
 *
 * Truncate the page cache, removing the pages that are between
 * specified offsets (and zeroing out partial pages
 * if lstart or lend + 1 is not page aligned).
 *
 * Truncate takes two passes - the first pass is nonblocking.  It will not
 * block on page locks and it will not block on writeback.  The second pass
 * will wait.  This is to prevent as much IO as possible in the affected region.
 * The first pass will remove most pages, so the search cost of the second pass
 * is low.
 *
 * We pass down the cache-hot hint to the page freeing code.  Even if the
 * mapping is large, it is probably the case that the final pages are the most
 * recently touched, and freeing happens in ascending file offset order.
 *
 * Note that since ->invalidatepage() accepts range to invalidate
 * truncate_inode_pages_range is able to handle cases where lend + 1 is not
 * page aligned properly.
 */
void truncate_inode_pages_range(struct address_space *mapping,
                loff_t lstart, loff_t lend)
{
    pgoff_t     start;      /* inclusive */
    pgoff_t     end;        /* exclusive */
    unsigned int    partial_start;  /* inclusive */
    unsigned int    partial_end;    /* exclusive */
    struct pagevec  pvec;
    pgoff_t     indices[PAGEVEC_SIZE];
    pgoff_t     index;
    int     i;

    printk("%s: ... (%lx, %lx)\n", __func__, lstart, lend);
    if (mapping->nrpages == 0 && mapping->nrexceptional == 0)
        goto out;

    /* Offsets within partial pages */
    partial_start = lstart & (PAGE_SIZE - 1);
    partial_end = (lend + 1) & (PAGE_SIZE - 1);

    /*
     * 'start' and 'end' always covers the range of pages to be fully
     * truncated. Partial pages are covered with 'partial_start' at the
     * start of the range and 'partial_end' at the end of the range.
     * Note that 'end' is exclusive while 'lend' is inclusive.
     */
    start = (lstart + PAGE_SIZE - 1) >> PAGE_SHIFT;
    if (lend == -1)
        /*
         * lend == -1 indicates end-of-file so we have to set 'end'
         * to the highest possible pgoff_t and since the type is
         * unsigned we're using -1.
         */
        end = -1;
    else
        end = (lend + 1) >> PAGE_SHIFT;

    pagevec_init(&pvec);
    index = start;
    while (index < end && pagevec_lookup_entries(&pvec, mapping, index,
            min(end - index, (pgoff_t)PAGEVEC_SIZE),
            indices)) {
        /*
         * Pagevec array has exceptional entries and we may also fail
         * to lock some pages. So we store pages that can be deleted
         * in a new pagevec.
         */
        struct pagevec locked_pvec;

        pagevec_init(&locked_pvec);
        for (i = 0; i < pagevec_count(&pvec); i++) {
            struct page *page = pvec.pages[i];

            /* We rely upon deletion not changing page->index */
            index = indices[i];
            if (index >= end)
                break;

            if (xa_is_value(page))
                continue;

            if (!trylock_page(page))
                continue;
            WARN_ON(page_to_index(page) != index);
            if (PageWriteback(page)) {
                unlock_page(page);
                continue;
            }
            if (page->mapping != mapping) {
                unlock_page(page);
                continue;
            }
            pagevec_add(&locked_pvec, page);
        }
        for (i = 0; i < pagevec_count(&locked_pvec); i++)
            truncate_cleanup_page(mapping, locked_pvec.pages[i]);
        delete_from_page_cache_batch(mapping, &locked_pvec);
        for (i = 0; i < pagevec_count(&locked_pvec); i++)
            unlock_page(locked_pvec.pages[i]);
        truncate_exceptional_pvec_entries(mapping, &pvec, indices, end);
        pagevec_release(&pvec);
        cond_resched();
        index++;
    }
    if (partial_start) {
        struct page *page = find_lock_page(mapping, start - 1);
        if (page) {
            unsigned int top = PAGE_SIZE;
            if (start > end) {
                /* Truncation within a single page */
                top = partial_end;
                partial_end = 0;
            }
            wait_on_page_writeback(page);
            zero_user_segment(page, partial_start, top);
            cleancache_invalidate_page(mapping, page);
            if (page_has_private(page))
                do_invalidatepage(page, partial_start,
                          top - partial_start);
            unlock_page(page);
            put_page(page);
        }
    }
    if (partial_end) {
        struct page *page = find_lock_page(mapping, end);
        if (page) {
            wait_on_page_writeback(page);
            zero_user_segment(page, 0, partial_end);
            cleancache_invalidate_page(mapping, page);
            if (page_has_private(page))
                do_invalidatepage(page, 0,
                          partial_end);
            unlock_page(page);
            put_page(page);
        }
    }
    /*
     * If the truncation happened within a single page no pages
     * will be released, just zeroed, so we can bail out now.
     */
    if (start >= end)
        goto out;

    index = start;
    for ( ; ; ) {
        cond_resched();
        if (!pagevec_lookup_entries(&pvec, mapping, index,
            min(end - index, (pgoff_t)PAGEVEC_SIZE), indices)) {
            /* If all gone from start onwards, we're done */
            if (index == start)
                break;
            /* Otherwise restart to make sure all gone */
            index = start;
            continue;
        }
        if (index == start && indices[0] >= end) {
            /* All gone out of hole to be punched, we're done */
            pagevec_remove_exceptionals(&pvec);
            pagevec_release(&pvec);
            break;
        }

        for (i = 0; i < pagevec_count(&pvec); i++) {
            struct page *page = pvec.pages[i];

            /* We rely upon deletion not changing page->index */
            index = indices[i];
            if (index >= end) {
                /* Restart punch to make sure all gone */
                index = start - 1;
                break;
            }

            if (xa_is_value(page))
                continue;

            lock_page(page);
            WARN_ON(page_to_index(page) != index);
            wait_on_page_writeback(page);
            truncate_inode_page(mapping, page);
            unlock_page(page);
        }
        truncate_exceptional_pvec_entries(mapping, &pvec, indices, end);
        pagevec_release(&pvec);
        index++;
    }

out:
    cleancache_invalidate_inode(mapping);
}

/**
 * truncate_inode_pages - truncate *all* the pages from an offset
 * @mapping: mapping to truncate
 * @lstart: offset from which to truncate
 *
 * Called under (and serialised by) inode->i_mutex.
 *
 * Note: When this function returns, there can be a page in the process of
 * deletion (inside __delete_from_page_cache()) in the specified range.  Thus
 * mapping->nrpages can be non-zero when this function returns even after
 * truncation of the whole mapping.
 */
void truncate_inode_pages(struct address_space *mapping, loff_t lstart)
{
    truncate_inode_pages_range(mapping, lstart, (loff_t)-1);
}
