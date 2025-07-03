#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/uio.h>
#include <linux/dax.h>
#include <linux/shmem_fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/gfp.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>

#include "ext2/ext2.h"
#include "mm/internal.h"
#include "booter.h"

/*
 * CD/DVDs are error prone. When a medium error occurs, the driver may fail
 * a _large_ part of the i/o request. Imagine the worst scenario:
 *
 *      ---R__________________________________________B__________
 *         ^ reading here                             ^ bad block(assume 4k)
 *
 * read(R) => miss => readahead(R...B) => media error => frustrating retries
 * => failing the whole request => read(R) => read(R+1) =>
 * readahead(R+1...B+1) => bang => read(R+2) => read(R+3) =>
 * readahead(R+3...B+2) => bang => read(R+3) => read(R+4) =>
 * readahead(R+4...B+3) => bang => read(R+4) => read(R+5) => ......
 *
 * It is going insane. Fix it by quickly scaling down the readahead size.
 */
static void shrink_readahead_size_eio(struct file_ra_state *ra)
{
    ra->ra_pages /= 4;
}

static void wake_up_page_bit(struct page *page, int bit_nr)
{
    booter_panic("%s: No impl.", __func__);
}

#ifndef clear_bit_unlock_is_negative_byte

/*
 * PG_waiters is the high bit in the same byte as PG_lock.
 *
 * On x86 (and on many other architectures), we can clear PG_lock and
 * test the sign bit at the same time. But if the architecture does
 * not support that special operation, we just do this all by hand
 * instead.
 *
 * The read of PG_waiters has to be after (or concurrently with) PG_locked
 * being cleared, but a memory barrier should be unnecessary since it is
 * in the same byte as PG_locked.
 */
static inline bool clear_bit_unlock_is_negative_byte(long nr, volatile void *mem)
{
    clear_bit_unlock(nr, mem);
    /* smp_mb__after_atomic(); */
    return test_bit(PG_waiters, mem);
}

#endif

struct page *read_cache_page(struct address_space *mapping,
                pgoff_t index,
                int (*filler)(void *, struct page *),
                void *data)
{
    printk("%s: mapping (%lx) index(%d) data(%x)\n",
                 __func__, mapping, index, data);

    struct buffer_head bh_result;
    memset(&bh_result, 0, sizeof(struct buffer_head));
    bh_result.b_size = 4096;

    sector_t iblock = 0;
    int ret = ext2_get_block(mapping->host, iblock, &bh_result, 0);
    if (ret < 0) {
        booter_panic("ext2_get_block error!");
    }

    // 4096 -> 512
    sector_t blknr = bh_result.b_blocknr * 8;
    log_error("%s: blknr(%u -> %u)\n",
              __func__, bh_result.b_blocknr, blknr);

    void *buf = alloc_pages_exact(PAGE_SIZE, 0);
    if (cl_read_block(blknr, buf, PAGE_SIZE) < 0) {
        booter_panic("read block error!");
    }

    struct page *page = virt_to_page(buf);
    init_page_count(page);
    page->mapping = mapping;
    page->index = index;
    return page;
}

/**
 * filemap_write_and_wait_range - write out & wait on a file range
 * @mapping:    the address_space for the pages
 * @lstart: offset in bytes where the range starts
 * @lend:   offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that @lend is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 *
 * Return: error status of the address space.
 */
int filemap_write_and_wait_range(struct address_space *mapping,
                 loff_t lstart, loff_t lend)
{
    log_error("%s: No impl.\n", __func__);
    return 0;
}

/**
 * generic_file_read_iter - generic filesystem read routine
 * @iocb:   kernel I/O control block
 * @iter:   destination for the data read
 *
 * This is the "read_iter()" routine for all filesystems
 * that can use the page cache directly.
 *
 * The IOCB_NOWAIT flag in iocb->ki_flags indicates that -EAGAIN shall
 * be returned when no data can be read without waiting for I/O requests
 * to complete; it doesn't prevent readahead.
 *
 * The IOCB_NOIO flag in iocb->ki_flags indicates that no new I/O
 * requests shall be made for the read or for readahead.  When no data
 * can be read, -EAGAIN shall be returned.  When readahead would be
 * triggered, a partial, possibly empty read shall be returned.
 *
 * Return:
 * * number of bytes copied, even for partial reads
 * * negative error code (or 0 if IOCB_NOIO) if nothing was read
 */
ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    size_t count = iov_iter_count(iter);
    ssize_t retval = 0;

    if (!count)
        goto out; /* skip atime */

    retval = generic_file_buffered_read(iocb, iter, retval);
out:
    return retval;
}

static int wait_on_page_locked_async(struct page *page,
                     struct wait_page_queue *wait)
{
    /*
    if (!PageLocked(page))
        return 0;
    return __wait_on_page_locked_async(compound_head(page), wait, false);
    */
    booter_panic("No impl.");
}

/**
 * generic_file_buffered_read - generic file read routine
 * @iocb:	the iocb to read
 * @iter:	data destination
 * @written:	already copied
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 *
 * Return:
 * * total number of bytes copied, including those the were already @written
 * * negative error code if nothing was copied
 */
ssize_t generic_file_buffered_read(struct kiocb *iocb,
		struct iov_iter *iter, ssize_t written)
{
	struct file *filp = iocb->ki_filp;
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	loff_t *ppos = &iocb->ki_pos;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	int error = 0;

	if (unlikely(*ppos >= inode->i_sb->s_maxbytes))
		return 0;
	iov_iter_truncate(iter, inode->i_sb->s_maxbytes);

	index = *ppos >> PAGE_SHIFT;
	prev_index = ra->prev_pos >> PAGE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_SIZE-1);
	last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
find_page:
		if (fatal_signal_pending(current)) {
			error = -EINTR;
			goto out;
		}

		page = find_get_page(mapping, index);

		if (!page) {
			if (iocb->ki_flags & IOCB_NOIO)
				goto would_block;
            goto no_cached_page;
		}
        /*
		if (PageReadahead(page)) {
			if (iocb->ki_flags & IOCB_NOIO) {
				put_page(page);
				goto out;
			}
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
        */
		if (!PageUptodate(page)) {
			/*
			 * See comment in do_read_cache_page on why
			 * wait_on_page_locked is used to avoid unnecessarily
			 * serialisations and why it's safe.
			 */
			if (iocb->ki_flags & IOCB_WAITQ) {
				if (written) {
					put_page(page);
					goto out;
				}
				error = wait_on_page_locked_async(page,
								iocb->ki_waitq);
			} else {
				if (iocb->ki_flags & IOCB_NOWAIT) {
					put_page(page);
					goto would_block;
				}
				error = wait_on_page_locked_killable(page);
			}
			if (unlikely(error))
				goto readpage_error;
			if (PageUptodate(page))
				goto page_ok;

			if (inode->i_blkbits == PAGE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				goto page_not_up_to_date;
			/* pipes can't handle partially uptodate pages */
			if (unlikely(iov_iter_is_pipe(iter)))
				goto page_not_up_to_date;
			if (!trylock_page(page))
				goto page_not_up_to_date;
			/* Did it get truncated before we got the lock? */
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			if (!mapping->a_ops->is_partially_uptodate(page,
							offset, iter->count))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}

page_ok:
		/*
		 * i_size must be checked after we know the page is Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */

		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			put_page(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset) {
				put_page(page);
				goto out;
			}
		}
		nr = nr - offset;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 */

		ret = copy_page_to_iter(page, offset, nr, iter);
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
		prev_offset = offset;

		put_page(page);
		written += ret;
		if (!iov_iter_count(iter))
			goto out;
		if (ret < nr) {
			error = -EFAULT;
			goto out;
		}
		continue;

page_not_up_to_date:
		/* Get exclusive access to the page ... */
		if (iocb->ki_flags & IOCB_WAITQ)
			error = lock_page_async(page, iocb->ki_waitq);
		else
			error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		/* Did it get truncated before we got the lock? */
		if (!page->mapping) {
			unlock_page(page);
			put_page(page);
			continue;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		if (iocb->ki_flags & (IOCB_NOIO | IOCB_NOWAIT)) {
			unlock_page(page);
			put_page(page);
			goto would_block;
		}
		/*
		 * A previous I/O error may have been due to temporary
		 * failures, eg. multipath errors.
		 * PG_error will be set again if readpage fails.
		 */
		ClearPageError(page);
		/* Start the actual read. The read will unlock the page. */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				put_page(page);
				error = 0;
				goto find_page;
			}
			goto readpage_error;
		}

		if (!PageUptodate(page)) {
            /*
			if (iocb->ki_flags & IOCB_WAITQ)
				error = lock_page_async(page, iocb->ki_waitq);
			else
				error = lock_page_killable(page);
            */

			if (unlikely(error))
				goto readpage_error;
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_mapping_pages got it
					 */
					unlock_page(page);
					put_page(page);
					goto find_page;
				}
				unlock_page(page);
				shrink_readahead_size_eio(ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		put_page(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		page = page_cache_alloc(mapping);
		if (!page) {
			error = -ENOMEM;
			goto out;
		}

		error = add_to_page_cache_lru(page, mapping, index,
				mapping_gfp_constraint(mapping, GFP_KERNEL));
		if (error) {
			put_page(page);
			if (error == -EEXIST) {
				error = 0;
				goto find_page;
			}
			goto out;
		}
		goto readpage;
	}

would_block:
	error = -EAGAIN;
out:
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_SHIFT) + offset;
	file_accessed(filp);
	return written ? written : error;
}

static int __add_to_page_cache_locked(struct page *page,
                      struct address_space *mapping,
                      pgoff_t offset, gfp_t gfp_mask,
                      void **shadowp)
{
    XA_STATE(xas, &mapping->i_pages, offset);
    int huge = PageHuge(page);
    int error;
    void *old;

    VM_BUG_ON_PAGE(!PageLocked(page), page);
    VM_BUG_ON_PAGE(PageSwapBacked(page), page);
    //mapping_set_update(&xas, mapping);

    get_page(page);
    page->mapping = mapping;
    page->index = offset;

    do {
        xas_lock_irq(&xas);
        old = xas_load(&xas);
        if (old && !xa_is_value(old))
            xas_set_err(&xas, -EEXIST);
        xas_store(&xas, page);
        if (xas_error(&xas))
            goto unlock;

        if (xa_is_value(old)) {
            mapping->nrexceptional--;
            if (shadowp)
                *shadowp = old;
        }
        mapping->nrpages++;

unlock:
        xas_unlock_irq(&xas);
    } while (xas_nomem(&xas, gfp_mask & GFP_RECLAIM_MASK));

	if (xas_error(&xas)) {
		error = xas_error(&xas);
		goto error;
	}

	return 0;
error:
	page->mapping = NULL;
	/* Leave page->index set: truncation relies upon it */
	put_page(page);
	return error;
}

int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
                pgoff_t offset, gfp_t gfp_mask)
{
    void *shadow = NULL;
    int ret;

    __SetPageLocked(page);
    ret = __add_to_page_cache_locked(page, mapping, offset,
                     gfp_mask, &shadow);
    if (unlikely(ret))
        __ClearPageLocked(page);

    return ret;
}

/**
 * pagecache_get_page - Find and get a reference to a page.
 * @mapping: The address_space to search.
 * @index: The page index.
 * @fgp_flags: %FGP flags modify how the page is returned.
 * @gfp_mask: Memory allocation flags to use if %FGP_CREAT is specified.
 *
 * Looks up the page cache entry at @mapping & @index.
 *
 * @fgp_flags can be zero or more of these flags:
 *
 * * %FGP_ACCESSED - The page will be marked accessed.
 * * %FGP_LOCK - The page is returned locked.
 * * %FGP_CREAT - If no page is present then a new page is allocated using
 *   @gfp_mask and added to the page cache and the VM's LRU list.
 *   The page is returned locked and with an increased refcount.
 * * %FGP_FOR_MMAP - The caller wants to do its own locking dance if the
 *   page is already in cache.  If the page was allocated, unlock it before
 *   returning so the caller can do the same dance.
 * * %FGP_WRITE - The page will be written
 * * %FGP_NOFS - __GFP_FS will get cleared in gfp mask
 * * %FGP_NOWAIT - Don't get blocked by page lock
 *
 * If %FGP_LOCK or %FGP_CREAT are specified then the function may sleep even
 * if the %GFP flags specified for %FGP_CREAT are atomic.
 *
 * If there is a page cache page, it is returned with an increased refcount.
 *
 * Return: The found page or %NULL otherwise.
 */
struct page *pagecache_get_page(struct address_space *mapping, pgoff_t index,
		int fgp_flags, gfp_t gfp_mask)
{
	struct page *page = find_get_entry(mapping, index);

    if (fgp_flags & FGP_LOCK) {
        if (fgp_flags & FGP_NOWAIT) {
            if (!trylock_page(page)) {
                put_page(page);
                return NULL;
            }
        } else {
            lock_page(page);
        }

        /* Has the page been truncated? */
        /*
        if (unlikely(compound_head(page)->mapping != mapping)) {
            unlock_page(page);
            put_page(page);
            goto repeat;
        }
        */
        VM_BUG_ON_PAGE(page->index != index, page);
    }
    return page;
}

/**
 * find_get_entry - find and get a page cache entry
 * @mapping: the address_space to search
 * @offset: the page cache index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned with an increased refcount.
 *
 * If the slot holds a shadow entry of a previously evicted page, or a
 * swap entry from shmem/tmpfs, it is returned.
 *
 * Return: the found page or shadow entry, %NULL if nothing is found.
 */
struct page *find_get_entry(struct address_space *mapping, pgoff_t offset)
{
    XA_STATE(xas, &mapping->i_pages, offset);
    struct page *page;

    rcu_read_lock();
repeat:
    xas_reset(&xas);
    page = xas_load(&xas);
    if (xas_retry(&xas, page))
        goto repeat;
    /*
     * A shadow entry of a recently evicted page, or a swap entry from
     * shmem/tmpfs.  Return it without attempting to raise page count.
     */
    if (!page || xa_is_value(page))
        goto out;

    if (!page_cache_get_speculative(page))
        goto repeat;

    /*
     * Has the page moved or been split?
     * This is part of the lockless pagecache protocol. See
     * include/linux/pagemap.h for details.
     */
    if (unlikely(page != xas_reload(&xas))) {
        put_page(page);
        goto repeat;
    }
    page = find_subpage(page, offset);
out:
    rcu_read_unlock();

    return page;
}

/**
 * unlock_page - unlock a locked page
 * @page: the page
 *
 * Unlocks the page and wakes up sleepers in ___wait_on_page_locked().
 * Also wakes sleepers in wait_on_page_writeback() because the wakeup
 * mechanism between PageLocked pages and PageWriteback pages is shared.
 * But that's OK - sleepers in wait_on_page_writeback() just go back to sleep.
 *
 * Note that this depends on PG_waiters being the sign bit in the byte
 * that contains PG_locked - thus the BUILD_BUG_ON(). That allows us to
 * clear the PG_locked bit and test PG_waiters at the same time fairly
 * portably (architectures that do LL/SC can test any bit, while x86 can
 * test the sign bit).
 */
void unlock_page(struct page *page)
{
    BUILD_BUG_ON(PG_waiters != 7);
    page = compound_head(page);
    VM_BUG_ON_PAGE(!PageLocked(page), page);
    if (clear_bit_unlock_is_negative_byte(PG_locked, &page->flags))
        wake_up_page_bit(page, PG_locked);
}

/*
 * Don't operate on ranges the page cache doesn't support, and don't exceed the
 * LFS limits.  If pos is under the limit it becomes a short access.  If it
 * exceeds the limit we return -EFBIG.
 */
static int generic_write_check_limits(struct file *file, loff_t pos,
                      loff_t *count)
{
    struct inode *inode = file->f_mapping->host;
    loff_t max_size = inode->i_sb->s_maxbytes;
    loff_t limit = rlimit(RLIMIT_FSIZE);

    if (limit != RLIM_INFINITY) {
        if (pos >= limit) {
            send_sig(SIGXFSZ, current, 0);
            return -EFBIG;
        }
        *count = min(*count, limit - pos);
    }

    if (!(file->f_flags & O_LARGEFILE))
        max_size = MAX_NON_LFS;

    if (unlikely(pos >= max_size))
        return -EFBIG;

    *count = min(*count, max_size - pos);

    return 0;
}

/*
 * Performs necessary checks before doing a write
 *
 * Can adjust writing position or amount of bytes to write.
 * Returns appropriate error code that caller should return or
 * zero in case that write should be allowed.
 */
inline ssize_t generic_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
    struct file *file = iocb->ki_filp;
    struct inode *inode = file->f_mapping->host;
    loff_t count;
    int ret;

    if (IS_SWAPFILE(inode))
        return -ETXTBSY;

    if (!iov_iter_count(from))
        return 0;

    /* FIXME: this is for backwards compatibility with 2.4 */
    if (iocb->ki_flags & IOCB_APPEND)
        iocb->ki_pos = i_size_read(inode);

    if ((iocb->ki_flags & IOCB_NOWAIT) && !(iocb->ki_flags & IOCB_DIRECT))
        return -EINVAL;

    count = iov_iter_count(from);
    ret = generic_write_check_limits(file, iocb->ki_pos, &count);
    if (ret)
        return ret;

    iov_iter_truncate(from, count);
    return iov_iter_count(from);
}

/*
 * Find or create a page at the given pagecache position. Return the locked
 * page. This function is specifically for buffered writes.
 */
struct page *grab_cache_page_write_begin(struct address_space *mapping,
                    pgoff_t index, unsigned flags)
{
    struct page *page;
    int fgp_flags = FGP_LOCK|FGP_WRITE|FGP_CREAT;

    if (flags & AOP_FLAG_NOFS)
        fgp_flags |= FGP_NOFS;

    page = pagecache_get_page(mapping, index, fgp_flags,
            mapping_gfp_mask(mapping));
    if (page)
        wait_for_stable_page(page);

    return page;
}

/* Returns true if writeback might be needed or already in progress. */
static bool mapping_needs_writeback(struct address_space *mapping)
{
    if (dax_mapping(mapping))
        return mapping->nrexceptional;

    return mapping->nrpages;
}

/**
 * __filemap_fdatawrite_range - start writeback on mapping dirty pages in range
 * @mapping:    address space structure to write
 * @start:  offset in bytes where the range starts
 * @end:    offset in bytes where the range ends (inclusive)
 * @sync_mode:  enable synchronous operation
 *
 * Start writeback against all of a mapping's dirty pages that lie
 * within the byte offsets <start, end> inclusive.
 *
 * If sync_mode is WB_SYNC_ALL then this is a "data integrity" operation, as
 * opposed to a regular memory cleansing writeback.  The difference between
 * these two operations is that if a dirty page/buffer is encountered, it must
 * be waited upon, and not just skipped over.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int __filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
                loff_t end, int sync_mode)
{
    int ret;
    struct writeback_control wbc = {
        .sync_mode = sync_mode,
        .nr_to_write = LONG_MAX,
        .range_start = start,
        .range_end = end,
    };

    // Note: impl mapping_cap_writeback_dirty(...).
    /*
    if (!mapping_cap_writeback_dirty(mapping) ||
        !mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
        return 0;
        */

    wbc_attach_fdatawrite_inode(&wbc, mapping->host);
    ret = do_writepages(mapping, &wbc);
    wbc_detach_inode(&wbc);
    return ret;
}

static void __filemap_fdatawait_range(struct address_space *mapping,
                     loff_t start_byte, loff_t end_byte)
{
    pgoff_t index = start_byte >> PAGE_SHIFT;
    pgoff_t end = end_byte >> PAGE_SHIFT;
    struct pagevec pvec;
    int nr_pages;

    if (end_byte < start_byte)
        return;

    pagevec_init(&pvec);
    while (index <= end) {
        unsigned i;

    printk("%s: step0\n", __func__);
        nr_pages = pagevec_lookup_range_tag(&pvec, mapping, &index,
                end, PAGECACHE_TAG_WRITEBACK);
        if (!nr_pages)
            break;

    printk("%s: step1\n", __func__);
        for (i = 0; i < nr_pages; i++) {
            struct page *page = pvec.pages[i];

            wait_on_page_writeback(page);
            ClearPageError(page);
        }
        pagevec_release(&pvec);
        cond_resched();
    }
}

/**
 * file_write_and_wait_range - write out & wait on a file range
 * @file:   file pointing to address_space with pages
 * @lstart: offset in bytes where the range starts
 * @lend:   offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that @lend is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 *
 * After writing out and waiting on the data, we check and advance the
 * f_wb_err cursor to the latest value, and return any errors detected there.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int file_write_and_wait_range(struct file *file, loff_t lstart, loff_t lend)
{
    int err = 0, err2;
    struct address_space *mapping = file->f_mapping;

    if (mapping_needs_writeback(mapping)) {
        err = __filemap_fdatawrite_range(mapping, lstart, lend,
                         WB_SYNC_ALL);
        /* See comment of filemap_write_and_wait() */
        if (err != -EIO)
            __filemap_fdatawait_range(mapping, lstart, lend);
    }
    err2 = file_check_and_advance_wb_err(file);
    if (!err)
        err = err2;
    return err;
}

/**
 * file_check_and_advance_wb_err - report wb error (if any) that was previously
 *                 and advance wb_err to current one
 * @file: struct file on which the error is being reported
 *
 * When userland calls fsync (or something like nfsd does the equivalent), we
 * want to report any writeback errors that occurred since the last fsync (or
 * since the file was opened if there haven't been any).
 *
 * Grab the wb_err from the mapping. If it matches what we have in the file,
 * then just quickly return 0. The file is all caught up.
 *
 * If it doesn't match, then take the mapping value, set the "seen" flag in
 * it and try to swap it into place. If it works, or another task beat us
 * to it with the new value, then update the f_wb_err and return the error
 * portion. The error at this point must be reported via proper channels
 * (a'la fsync, or NFS COMMIT operation, etc.).
 *
 * While we handle mapping->wb_err with atomic operations, the f_wb_err
 * value is protected by the f_lock since we must ensure that it reflects
 * the latest value swapped in for this file descriptor.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int file_check_and_advance_wb_err(struct file *file)
{
    int err = 0;
    errseq_t old = READ_ONCE(file->f_wb_err);
    struct address_space *mapping = file->f_mapping;

    /* Locklessly handle the common case where nothing has changed */
    if (errseq_check(&mapping->wb_err, old)) {
        /* Something changed, must use slow path */
        spin_lock(&file->f_lock);
        old = file->f_wb_err;
        err = errseq_check_and_advance(&mapping->wb_err,
                        &file->f_wb_err);
        //trace_file_check_and_advance_wb_err(file, old);
        spin_unlock(&file->f_lock);
    }

    /*
     * We're mostly using this function as a drop in replacement for
     * filemap_check_errors. Clear AS_EIO/AS_ENOSPC to emulate the effect
     * that the legacy code would have had on these flags.
     */
    clear_bit(AS_EIO, &mapping->flags);
    clear_bit(AS_ENOSPC, &mapping->flags);
    return err;
}

/**
 * find_get_pages_range_tag - find and return pages in given range matching @tag
 * @mapping:    the address_space to search
 * @index:  the starting page index
 * @end:    The final page index (inclusive)
 * @tag:    the tag index
 * @nr_pages:   the maximum number of pages
 * @pages:  where the resulting pages are placed
 *
 * Like find_get_pages, except we only return pages which are tagged with
 * @tag.   We update @index to index the next page for the traversal.
 *
 * Return: the number of pages which were found.
 */
unsigned find_get_pages_range_tag(struct address_space *mapping, pgoff_t *index,
            pgoff_t end, xa_mark_t tag, unsigned int nr_pages,
            struct page **pages)
{
    XA_STATE(xas, &mapping->i_pages, *index);
    struct page *page;
    unsigned ret = 0;

    if (unlikely(!nr_pages))
        return 0;

    rcu_read_lock();
    xas_for_each_marked(&xas, page, end, tag) {
        if (xas_retry(&xas, page))
            continue;
        /*
         * Shadow entries should never be tagged, but this iteration
         * is lockless so there is a window for page reclaim to evict
         * a page we saw tagged.  Skip over it.
         */
        if (xa_is_value(page))
            continue;

        if (!page_cache_get_speculative(page))
            goto retry;

        /* Has the page moved or been split? */
        if (unlikely(page != xas_reload(&xas)))
            goto put_page;

        pages[ret] = find_subpage(page, xas.xa_index);
        if (++ret == nr_pages) {
            *index = xas.xa_index + 1;
            goto out;
        }
        continue;
put_page:
        put_page(page);
retry:
        xas_reset(&xas);
    }

    /*
     * We come here when we got to @end. We take care to not overflow the
     * index @index as it confuses some of the callers. This breaks the
     * iteration when there is a page at index -1 but that is already
     * broken anyway.
     */
    if (end == (pgoff_t)-1)
        *index = (pgoff_t)-1;
    else
        *index = end + 1;
out:
    rcu_read_unlock();

    return ret;
}
