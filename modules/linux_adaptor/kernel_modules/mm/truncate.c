#include <linux/kernel.h>
#include <linux/backing-dev.h>
#include <linux/dax.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/export.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/pagevec.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/shmem_fs.h>
#include <linux/rmap.h>
#include "internal.h"

#include "../adaptor.h"

/*
 * Regular page slots are stabilized by the page lock even without the tree
 * itself locked.  These unlocked entries need verification under the tree
 * lock.
 */
static inline void __clear_shadow_entry(struct address_space *mapping,
                pgoff_t index, void *entry)
{
    XA_STATE(xas, &mapping->i_pages, index);

    xas_set_update(&xas, workingset_update_node);
    if (xas_load(&xas) != entry)
        return;
    xas_store(&xas, NULL);
}

/*
 * Unconditionally remove exceptional entries. Usually called from truncate
 * path. Note that the folio_batch may be altered by this function by removing
 * exceptional entries similar to what folio_batch_remove_exceptionals() does.
 */
static void truncate_folio_batch_exceptionals(struct address_space *mapping,
                struct folio_batch *fbatch, pgoff_t *indices)
{
    int i, j;
    bool dax;

    /* Handled by shmem itself */
    if (shmem_mapping(mapping))
        return;

    for (j = 0; j < folio_batch_count(fbatch); j++)
        if (xa_is_value(fbatch->folios[j]))
            break;

    if (j == folio_batch_count(fbatch))
        return;

    dax = dax_mapping(mapping);
    if (!dax) {
        spin_lock(&mapping->host->i_lock);
        xa_lock_irq(&mapping->i_pages);
    }

    for (i = j; i < folio_batch_count(fbatch); i++) {
        struct folio *folio = fbatch->folios[i];
        pgoff_t index = indices[i];

        if (!xa_is_value(folio)) {
            fbatch->folios[j++] = folio;
            continue;
        }

        if (unlikely(dax)) {
            dax_delete_mapping_entry(mapping, index);
            continue;
        }

        __clear_shadow_entry(mapping, index, folio);
    }

    if (!dax) {
        xa_unlock_irq(&mapping->i_pages);
        if (mapping_shrinkable(mapping))
            inode_add_lru(mapping->host);
        spin_unlock(&mapping->host->i_lock);
    }
    fbatch->nr = j;

    PANIC("");
}

/*
 * If truncate cannot remove the fs-private metadata from the page, the page
 * becomes orphaned.  It will be left on the LRU and may even be mapped into
 * user pagetables if we're racing with filemap_fault().
 *
 * We need to bail out if page->mapping is no longer equal to the original
 * mapping.  This happens a) when the VM reclaimed the page while we waited on
 * its lock, b) when a concurrent invalidate_mapping_pages got there first and
 * c) when tmpfs swizzles a page between a tmpfs inode and swapper_space.
 */
static void truncate_cleanup_folio(struct folio *folio)
{
    if (folio_mapped(folio))
        unmap_mapping_folio(folio);

    printk("%s: ======== step1 (%lx)\n", __func__, folio->mapping);
    if (folio_needs_release(folio))
        folio_invalidate(folio, 0, folio_size(folio));

    printk("%s: ======== step2\n", __func__);
    /*
     * Some filesystems seem to re-dirty the page even after
     * the VM has canceled the dirty bit (eg ext3 journaling).
     * Hence dirty accounting check is placed after invalidation.
     */
    folio_cancel_dirty(folio);
    folio_clear_mappedtodisk(folio);
}

/**
 * truncate_inode_pages - truncate *all* the pages from an offset
 * @mapping: mapping to truncate
 * @lstart: offset from which to truncate
 *
 * Called under (and serialised by) inode->i_rwsem and
 * mapping->invalidate_lock.
 *
 * Note: When this function returns, there can be a page in the process of
 * deletion (inside __filemap_remove_folio()) in the specified range.  Thus
 * mapping->nrpages can be non-zero when this function returns even after
 * truncation of the whole mapping.
 */
void truncate_inode_pages(struct address_space *mapping, loff_t lstart)
{
    truncate_inode_pages_range(mapping, lstart, (loff_t)-1);
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
 * Note that since ->invalidate_folio() accepts range to invalidate
 * truncate_inode_pages_range is able to handle cases where lend + 1 is not
 * page aligned properly.
 */
void truncate_inode_pages_range(struct address_space *mapping,
                loff_t lstart, loff_t lend)
{
    pgoff_t     start;      /* inclusive */
    pgoff_t     end;        /* exclusive */
    struct folio_batch fbatch;
    pgoff_t     indices[PAGEVEC_SIZE];
    pgoff_t     index;
    int     i;
    struct folio    *folio;
    bool        same_folio;

    if (mapping_empty(mapping))
        return;

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

    folio_batch_init(&fbatch);
    index = start;
    printk("%s: ======== step0\n", __func__);
    while (index < end && find_lock_entries(mapping, &index, end - 1,
            &fbatch, indices)) {
        truncate_folio_batch_exceptionals(mapping, &fbatch, indices);
    printk("%s: ======== step1\n", __func__);
        for (i = 0; i < folio_batch_count(&fbatch); i++)
            truncate_cleanup_folio(fbatch.folios[i]);
    printk("%s: ======== step2\n", __func__);
        delete_from_page_cache_batch(mapping, &fbatch);
        for (i = 0; i < folio_batch_count(&fbatch); i++)
            folio_unlock(fbatch.folios[i]);
        folio_batch_release(&fbatch);
        cond_resched();
    }

    same_folio = (lstart >> PAGE_SHIFT) == (lend >> PAGE_SHIFT);
    folio = __filemap_get_folio(mapping, lstart >> PAGE_SHIFT, FGP_LOCK, 0);
    if (!IS_ERR(folio)) {
        same_folio = lend < folio_pos(folio) + folio_size(folio);
        if (!truncate_inode_partial_folio(folio, lstart, lend)) {
            start = folio_next_index(folio);
            if (same_folio)
                end = folio->index;
        }
        folio_unlock(folio);
        folio_put(folio);
        folio = NULL;
    }
    if (!same_folio) {
        folio = __filemap_get_folio(mapping, lend >> PAGE_SHIFT,
                        FGP_LOCK, 0);
        if (!IS_ERR(folio)) {
            if (!truncate_inode_partial_folio(folio, lstart, lend))
                end = folio->index;
            folio_unlock(folio);
            folio_put(folio);
        }
    }

    index = start;
    while (index < end) {
        cond_resched();
        if (!find_get_entries(mapping, &index, end - 1, &fbatch,
                indices)) {
            /* If all gone from start onwards, we're done */
            if (index == start)
                break;
            /* Otherwise restart to make sure all gone */
            index = start;
            continue;
        }

        for (i = 0; i < folio_batch_count(&fbatch); i++) {
            struct folio *folio = fbatch.folios[i];

            /* We rely upon deletion not changing page->index */

            if (xa_is_value(folio))
                continue;

            folio_lock(folio);
            VM_BUG_ON_FOLIO(!folio_contains(folio, indices[i]), folio);
            folio_wait_writeback(folio);
            truncate_inode_folio(mapping, folio);
            folio_unlock(folio);
        }
        truncate_folio_batch_exceptionals(mapping, &fbatch, indices);
        folio_batch_release(&fbatch);
    }
}

/**
 * folio_invalidate - Invalidate part or all of a folio.
 * @folio: The folio which is affected.
 * @offset: start of the range to invalidate
 * @length: length of the range to invalidate
 *
 * folio_invalidate() is called when all or part of the folio has become
 * invalidated by a truncate operation.
 *
 * folio_invalidate() does not have to release all buffers, but it must
 * ensure that no dirty buffer is left outside @offset and that no I/O
 * is underway against any of the blocks which are outside the truncation
 * point.  Because the caller is about to free (and possibly reuse) those
 * blocks on-disk.
 */
void folio_invalidate(struct folio *folio, size_t offset, size_t length)
{
    printk("%s: ======== step0 (%lx)\n", __func__, folio->mapping);
    const struct address_space_operations *aops = folio->mapping->a_ops;

    printk("%s: ======== step1\n", __func__);
    if (aops->invalidate_folio)
        aops->invalidate_folio(folio, offset, length);
}

/**
 * invalidate_mapping_pages - Invalidate all clean, unlocked cache of one inode
 * @mapping: the address_space which holds the cache to invalidate
 * @start: the offset 'from' which to invalidate
 * @end: the offset 'to' which to invalidate (inclusive)
 *
 * This function removes pages that are clean, unmapped and unlocked,
 * as well as shadow entries. It will not block on IO activity.
 *
 * If you want to remove all the pages of one inode, regardless of
 * their use and writeback state, use truncate_inode_pages().
 *
 * Return: The number of indices that had their contents invalidated
 */
unsigned long invalidate_mapping_pages(struct address_space *mapping,
        pgoff_t start, pgoff_t end)
{
    return mapping_try_invalidate(mapping, start, end, NULL);
}

static void clear_shadow_entries(struct address_space *mapping,
                 struct folio_batch *fbatch, pgoff_t *indices)
{
    int i;

#if 0
    /* Handled by shmem itself, or for DAX we do nothing. */
    if (shmem_mapping(mapping) || dax_mapping(mapping))
        return;

    spin_lock(&mapping->host->i_lock);
    xa_lock_irq(&mapping->i_pages);

    for (i = 0; i < folio_batch_count(fbatch); i++) {
        struct folio *folio = fbatch->folios[i];

        if (xa_is_value(folio))
            __clear_shadow_entry(mapping, indices[i], folio);
    }

    xa_unlock_irq(&mapping->i_pages);
    if (mapping_shrinkable(mapping))
        inode_add_lru(mapping->host);
    spin_unlock(&mapping->host->i_lock);
#endif
    PANIC("");
}

/**
 * mapping_evict_folio() - Remove an unused folio from the page-cache.
 * @mapping: The mapping this folio belongs to.
 * @folio: The folio to remove.
 *
 * Safely remove one folio from the page cache.
 * It only drops clean, unused folios.
 *
 * Context: Folio must be locked.
 * Return: The number of pages successfully removed.
 */
long mapping_evict_folio(struct address_space *mapping, struct folio *folio)
{
    /* The page may have been truncated before it was locked */
    if (!mapping)
        return 0;
    if (folio_test_dirty(folio) || folio_test_writeback(folio))
        return 0;
    /* The refcount will be elevated if any page in the folio is mapped */
    if (folio_ref_count(folio) >
            folio_nr_pages(folio) + folio_has_private(folio) + 1)
        return 0;
#if 0
    if (!filemap_release_folio(folio, 0))
        return 0;

    return remove_mapping(mapping, folio);
#endif
    PANIC("");
}

/**
 * mapping_try_invalidate - Invalidate all the evictable folios of one inode
 * @mapping: the address_space which holds the folios to invalidate
 * @start: the offset 'from' which to invalidate
 * @end: the offset 'to' which to invalidate (inclusive)
 * @nr_failed: How many folio invalidations failed
 *
 * This function is similar to invalidate_mapping_pages(), except that it
 * returns the number of folios which could not be evicted in @nr_failed.
 */
unsigned long mapping_try_invalidate(struct address_space *mapping,
        pgoff_t start, pgoff_t end, unsigned long *nr_failed)
{
    pgoff_t indices[PAGEVEC_SIZE];
    struct folio_batch fbatch;
    pgoff_t index = start;
    unsigned long ret;
    unsigned long count = 0;
    int i;
    bool xa_has_values = false;

    folio_batch_init(&fbatch);
    while (find_lock_entries(mapping, &index, end, &fbatch, indices)) {
        for (i = 0; i < folio_batch_count(&fbatch); i++) {
            struct folio *folio = fbatch.folios[i];

            /* We rely upon deletion not changing folio->index */

            if (xa_is_value(folio)) {
                xa_has_values = true;
                count++;
                continue;
            }

            ret = mapping_evict_folio(mapping, folio);
            folio_unlock(folio);
            /*
             * Invalidation is a hint that the folio is no longer
             * of interest and try to speed up its reclaim.
             */
            if (!ret) {
                deactivate_file_folio(folio);
                /* Likely in the lru cache of a remote CPU */
                if (nr_failed)
                    (*nr_failed)++;
            }
            count += ret;
        }

        if (xa_has_values)
            clear_shadow_entries(mapping, &fbatch, indices);

        folio_batch_remove_exceptionals(&fbatch);
        folio_batch_release(&fbatch);
        cond_resched();
    }
    return count;
}
