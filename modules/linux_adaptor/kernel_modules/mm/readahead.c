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

#if 0
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
readit:
    ractl->_index = ra->start;
    page_cache_ra_order(ractl, ra, 0);
#endif
    PANIC("");
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
    PANIC("");
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
