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
