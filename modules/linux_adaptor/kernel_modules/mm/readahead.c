#include <linux/blkdev.h>
#include <linux/kernel.h>
#include <linux/dax.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/backing-dev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/pagemap.h>
#include <linux/psi.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/mm_inline.h>
#include <linux/blk-cgroup.h>
#include <linux/fadvise.h>
#include <linux/sched/mm.h>

#include "internal.h"

#include "../adaptor.h"

/*
 * Initialise a struct file's readahead state.  Assumes that the caller has
 * memset *ra to zero.
 */
void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping)
{
    ra->ra_pages = inode_to_bdi(mapping->host)->ra_pages;
    ra->prev_pos = -1;
}

static void read_pages(struct readahead_control *rac)
{
    const struct address_space_operations *aops = rac->mapping->a_ops;
    struct folio *folio;
    struct blk_plug plug;

    if (!readahead_count(rac))
        return;

    if (unlikely(rac->_workingset))
        psi_memstall_enter(&rac->_pflags);
    blk_start_plug(&plug);

    if (aops->readahead) {
        aops->readahead(rac);
        /*
         * Clean up the remaining folios.  The sizes in ->ra
         * may be used to size the next readahead, so make sure
         * they accurately reflect what happened.
         */
        while ((folio = readahead_folio(rac)) != NULL) {
            unsigned long nr = folio_nr_pages(folio);

            folio_get(folio);
            rac->ra->size -= nr;
            if (rac->ra->async_size >= nr) {
                rac->ra->async_size -= nr;
                filemap_remove_folio(folio);
            }
            folio_unlock(folio);
            folio_put(folio);
        }
    } else {
        PANIC("No aops->readahead");
    }

    blk_finish_plug(&plug);
    if (unlikely(rac->_workingset))
        psi_memstall_leave(&rac->_pflags);
    rac->_workingset = false;

    BUG_ON(readahead_count(rac));
}

/*
 * do_page_cache_ra() actually reads a chunk of disk.  It allocates
 * the pages first, then submits them for I/O. This avoids the very bad
 * behaviour which would occur if page allocations are causing VM writeback.
 * We really don't want to intermingle reads and writes like that.
 */
static void do_page_cache_ra(struct readahead_control *ractl,
        unsigned long nr_to_read, unsigned long lookahead_size)
{
    struct inode *inode = ractl->mapping->host;
    unsigned long index = readahead_index(ractl);
    loff_t isize = i_size_read(inode);
    pgoff_t end_index;  /* The last page we want to read */

    if (isize == 0)
        return;

    end_index = (isize - 1) >> PAGE_SHIFT;
    if (index > end_index)
        return;
    /* Don't read past the page containing the last byte of the file */
    if (nr_to_read > end_index - index)
        nr_to_read = end_index - index + 1;

    page_cache_ra_unbounded(ractl, nr_to_read, lookahead_size);
}

/*
 * Set the initial window size, round to next power of 2 and square
 * for small size, x 4 for medium, and x 2 for large
 * for 128k (32 page) max ra
 * 1-2 page = 16k, 3-4 page 32k, 5-8 page = 64k, > 8 page = 128k initial
 */
static unsigned long get_init_ra_size(unsigned long size, unsigned long max)
{
    unsigned long newsize = roundup_pow_of_two(size);

    if (newsize <= max / 32)
        newsize = newsize * 4;
    else if (newsize <= max / 4)
        newsize = newsize * 2;
    else
        newsize = max;

    return newsize;
}

static unsigned long ractl_max_pages(struct readahead_control *ractl,
        unsigned long req_size)
{
    struct backing_dev_info *bdi = inode_to_bdi(ractl->mapping->host);
    unsigned long max_pages = ractl->ra->ra_pages;

    /*
     * If the request exceeds the readahead window, allow the read to
     * be up to the optimal hardware IO size
     */
    if (req_size > max_pages && bdi->io_pages > max_pages)
        max_pages = min(req_size, bdi->io_pages);
    return max_pages;
}

void page_cache_sync_ra(struct readahead_control *ractl,
        unsigned long req_count)
{
    pgoff_t index = readahead_index(ractl);
    bool do_forced_ra = ractl->file && (ractl->file->f_mode & FMODE_RANDOM);
    struct file_ra_state *ra = ractl->ra;
    unsigned long max_pages, contig_count;
    pgoff_t prev_index, miss;

    /*
     * Even if readahead is disabled, issue this request as readahead
     * as we'll need it to satisfy the requested range. The forced
     * readahead will do the right thing and limit the read to just the
     * requested range, which we'll set to 1 page for this case.
     */
    if (!ra->ra_pages || blk_cgroup_congested()) {
        if (!ractl->file)
            return;
        req_count = 1;
        do_forced_ra = true;
    }

    /* be dumb */
    if (do_forced_ra) {
        force_page_cache_ra(ractl, req_count);
        return;
    }

    max_pages = ractl_max_pages(ractl, req_count);
    prev_index = (unsigned long long)ra->prev_pos >> PAGE_SHIFT;
    /*
     * A start of file, oversized read, or sequential cache miss:
     * trivial case: (index - prev_index) == 1
     * unaligned reads: (index - prev_index) == 0
     */
    if (!index || req_count > max_pages || index - prev_index <= 1UL) {
        ra->start = index;
        ra->size = get_init_ra_size(req_count, max_pages);
        ra->async_size = ra->size > req_count ? ra->size - req_count :
                            ra->size >> 1;
        goto readit;
    }

#if 0
    /*
     * Query the page cache and look for the traces(cached history pages)
     * that a sequential stream would leave behind.
     */
    rcu_read_lock();
    miss = page_cache_prev_miss(ractl->mapping, index - 1, max_pages);
    rcu_read_unlock();
    contig_count = index - miss - 1;
    /*
     * Standalone, small random read. Read as is, and do not pollute the
     * readahead state.
     */
    if (contig_count <= req_count) {
        do_page_cache_ra(ractl, req_count, 0);
        return;
    }
    /*
     * File cached from the beginning:
     * it is a strong indication of long-run stream (or whole-file-read)
     */
    if (miss == ULONG_MAX)
        contig_count *= 2;
    ra->start = index;
    ra->size = min(contig_count + req_count, max_pages);
    ra->async_size = 1;
#endif
    PANIC("");
readit:
    ractl->_index = ra->start;
    page_cache_ra_order(ractl, ra, 0);
}

/*
 * Chunk the readahead into 2 megabyte units, so that we don't pin too much
 * memory at once.
 */
void force_page_cache_ra(struct readahead_control *ractl,
        unsigned long nr_to_read)
{
    struct address_space *mapping = ractl->mapping;
    struct file_ra_state *ra = ractl->ra;
    struct backing_dev_info *bdi = inode_to_bdi(mapping->host);
    unsigned long max_pages;

    if (unlikely(!mapping->a_ops->read_folio && !mapping->a_ops->readahead))
        return;

    /*
     * If the request exceeds the readahead window, allow the read to
     * be up to the optimal hardware IO size
     */
    max_pages = max_t(unsigned long, bdi->io_pages, ra->ra_pages);
    nr_to_read = min_t(unsigned long, nr_to_read, max_pages);
    while (nr_to_read) {
        unsigned long this_chunk = (2 * 1024 * 1024) / PAGE_SIZE;

        if (this_chunk > nr_to_read)
            this_chunk = nr_to_read;
        do_page_cache_ra(ractl, this_chunk, 0);

        nr_to_read -= this_chunk;
    }
}

/**
 * page_cache_ra_unbounded - Start unchecked readahead.
 * @ractl: Readahead control.
 * @nr_to_read: The number of pages to read.
 * @lookahead_size: Where to start the next readahead.
 *
 * This function is for filesystems to call when they want to start
 * readahead beyond a file's stated i_size.  This is almost certainly
 * not the function you want to call.  Use page_cache_async_readahead()
 * or page_cache_sync_readahead() instead.
 *
 * Context: File is referenced by caller.  Mutexes may be held by caller.
 * May sleep, but will not reenter filesystem to reclaim memory.
 */
void page_cache_ra_unbounded(struct readahead_control *ractl,
        unsigned long nr_to_read, unsigned long lookahead_size)
{
    struct address_space *mapping = ractl->mapping;
    unsigned long ra_folio_index, index = readahead_index(ractl);
    gfp_t gfp_mask = readahead_gfp_mask(mapping);
    unsigned long mark, i = 0;
    unsigned int min_nrpages = mapping_min_folio_nrpages(mapping);

    /*
     * Partway through the readahead operation, we will have added
     * locked pages to the page cache, but will not yet have submitted
     * them for I/O.  Adding another page may need to allocate memory,
     * which can trigger memory reclaim.  Telling the VM we're in
     * the middle of a filesystem operation will cause it to not
     * touch file-backed pages, preventing a deadlock.  Most (all?)
     * filesystems already specify __GFP_NOFS in their mapping's
     * gfp_mask, but let's be explicit here.
     */
    unsigned int nofs = memalloc_nofs_save();

    filemap_invalidate_lock_shared(mapping);
    index = mapping_align_index(mapping, index);

    /*
     * As iterator `i` is aligned to min_nrpages, round_up the
     * difference between nr_to_read and lookahead_size to mark the
     * index that only has lookahead or "async_region" to set the
     * readahead flag.
     */
    ra_folio_index = round_up(readahead_index(ractl) + nr_to_read - lookahead_size,
                  min_nrpages);
    mark = ra_folio_index - index;
    nr_to_read += readahead_index(ractl) - index;
    ractl->_index = index;

    /*
     * Preallocate as many pages as we will need.
     */
    while (i < nr_to_read) {
        struct folio *folio = xa_load(&mapping->i_pages, index + i);
        int ret;

        if (folio && !xa_is_value(folio)) {
            /*
             * Page already present?  Kick off the current batch
             * of contiguous pages before continuing with the
             * next batch.  This page may be the one we would
             * have intended to mark as Readahead, but we don't
             * have a stable reference to this page, and it's
             * not worth getting one just for that.
             */
            read_pages(ractl);
            ractl->_index += min_nrpages;
            i = ractl->_index + ractl->_nr_pages - index;
            continue;
        }

        folio = filemap_alloc_folio(gfp_mask,
                        mapping_min_folio_order(mapping));
        if (!folio)
            break;

        ret = filemap_add_folio(mapping, folio, index + i, gfp_mask);
        if (ret < 0) {
            folio_put(folio);
            if (ret == -ENOMEM)
                break;
            read_pages(ractl);
            ractl->_index += min_nrpages;
            i = ractl->_index + ractl->_nr_pages - index;
            continue;
        }
        if (i == mark)
            folio_set_readahead(folio);
        ractl->_workingset |= folio_test_workingset(folio);
        ractl->_nr_pages += min_nrpages;
        i += min_nrpages;
    }

    /*
     * Now start the IO.  We ignore I/O errors - if the folio is not
     * uptodate then the caller will launch read_folio again, and
     * will then handle the error.
     */
    read_pages(ractl);
    filemap_invalidate_unlock_shared(mapping);
    memalloc_nofs_restore(nofs);
}

void page_cache_async_ra(struct readahead_control *ractl,
        struct folio *folio, unsigned long req_count)
{
    unsigned long max_pages;
    struct file_ra_state *ra = ractl->ra;
    pgoff_t index = readahead_index(ractl);
    pgoff_t expected, start;
    unsigned int order = folio_order(folio);

    /* no readahead */
    if (!ra->ra_pages)
        return;

    PANIC("");
}

void page_cache_ra_order(struct readahead_control *ractl,
        struct file_ra_state *ra, unsigned int new_order)
{
    struct address_space *mapping = ractl->mapping;
    pgoff_t index = readahead_index(ractl);
    unsigned int min_order = mapping_min_folio_order(mapping);
    pgoff_t limit = (i_size_read(mapping->host) - 1) >> PAGE_SHIFT;
    pgoff_t mark = index + ra->size - ra->async_size;
    unsigned int nofs;
    int err = 0;
    gfp_t gfp = readahead_gfp_mask(mapping);
    unsigned int min_ra_size = max(4, mapping_min_folio_nrpages(mapping));

    /*
     * Fallback when size < min_nrpages as each folio should be
     * at least min_nrpages anyway.
     */
    if (!mapping_large_folio_support(mapping) || ra->size < min_ra_size)
        goto fallback;

#if 0
    limit = min(limit, index + ra->size - 1);

    if (new_order < mapping_max_folio_order(mapping))
        new_order += 2;

    new_order = min(mapping_max_folio_order(mapping), new_order);
    new_order = min_t(unsigned int, new_order, ilog2(ra->size));
    new_order = max(new_order, min_order);

    /* See comment in page_cache_ra_unbounded() */
    nofs = memalloc_nofs_save();
    filemap_invalidate_lock_shared(mapping);
    /*
     * If the new_order is greater than min_order and index is
     * already aligned to new_order, then this will be noop as index
     * aligned to new_order should also be aligned to min_order.
     */
    ractl->_index = mapping_align_index(mapping, index);
    index = readahead_index(ractl);

    while (index <= limit) {
        unsigned int order = new_order;

        /* Align with smaller pages if needed */
        if (index & ((1UL << order) - 1))
            order = __ffs(index);
        /* Don't allocate pages past EOF */
        while (order > min_order && index + (1UL << order) - 1 > limit)
            order--;
        err = ra_alloc_folio(ractl, index, mark, order, gfp);
        if (err)
            break;
        index += 1UL << order;
    }

    read_pages(ractl);
    filemap_invalidate_unlock_shared(mapping);
    memalloc_nofs_restore(nofs);
#endif

    PANIC("");
    /*
     * If there were already pages in the page cache, then we may have
     * left some gaps.  Let the regular readahead code take care of this
     * situation.
     */
    if (!err)
        return;
fallback:
    do_page_cache_ra(ractl, ra->size, ra->async_size);
}
