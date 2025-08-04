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
#include <linux/page_idle.h>
#include <linux/delayacct.h>
#include <linux/psi.h>

#include "ext2/ext2.h"
#include "mm/internal.h"
#include "booter.h"

/*
 * A choice of three behaviors for wait_on_page_bit_common():
 */
enum behavior {
    EXCLUSIVE,  /* Hold ref to page and take the bit when woken, like
             * __lock_page() waiting on then setting PG_locked.
             */
    SHARED,     /* Hold ref to page and check the bit when woken, like
             * wait_on_page_writeback() waiting on PG_writeback.
             */
    DROP,       /* Drop ref to page before wait, no check when woken,
             * like put_and_wait_on_page_locked() on PG_locked.
             */
};

/*
 * Attempt to check (or get) the page bit, and mark us done
 * if successful.
 */
static inline bool trylock_page_bit_common(struct page *page, int bit_nr,
                    struct wait_queue_entry *wait)
{
    if (wait->flags & WQ_FLAG_EXCLUSIVE) {
        if (test_and_set_bit(bit_nr, &page->flags))
            return false;
    } else if (test_bit(bit_nr, &page->flags))
        return false;

    wait->flags |= WQ_FLAG_WOKEN | WQ_FLAG_DONE;
    return true;
}

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
#define PAGE_WAIT_TABLE_BITS 8
#define PAGE_WAIT_TABLE_SIZE (1 << PAGE_WAIT_TABLE_BITS)
static wait_queue_head_t page_wait_table[PAGE_WAIT_TABLE_SIZE] __cacheline_aligned;

static wait_queue_head_t *page_waitqueue(struct page *page)
{
    return &page_wait_table[hash_ptr(page, PAGE_WAIT_TABLE_BITS)];
}

/* Returns true if writeback might be needed or already in progress. */
static bool mapping_needs_writeback(struct address_space *mapping)
{
    if (dax_mapping(mapping))
        return mapping->nrexceptional;

    return mapping->nrpages;
}

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
    log_error("%s: bit_nr(%d) ...\n", __func__, bit_nr);

    wait_queue_head_t *q = page_waitqueue(page);
    struct wait_page_key key;
    unsigned long flags;
    wait_queue_entry_t bookmark;

    key.page = page;
    key.bit_nr = bit_nr;
    key.page_match = 0;

    bookmark.flags = 0;
    bookmark.private = NULL;
    bookmark.func = NULL;
    INIT_LIST_HEAD(&bookmark.entry);

    spin_lock_irqsave(&q->lock, flags);
    __wake_up_locked_key_bookmark(q, TASK_NORMAL, &key, &bookmark);

    while (bookmark.flags & WQ_FLAG_BOOKMARK) {
        /*
         * Take a breather from holding the lock,
         * allow pages that finish wake up asynchronously
         * to acquire the lock and remove themselves
         * from wait queue
         */
        spin_unlock_irqrestore(&q->lock, flags);
        cpu_relax();
        spin_lock_irqsave(&q->lock, flags);
        __wake_up_locked_key_bookmark(q, TASK_NORMAL, &key, &bookmark);
    }

    /*
     * It is possible for other pages to have collided on the waitqueue
     * hash, so in that case check for a page match. That prevents a long-
     * term waiter
     *
     * It is still possible to miss a case here, when we woke page waiters
     * and removed them from the waitqueue, but there are still other
     * page waiters.
     */
    if (!waitqueue_active(q) || !key.page_match) {
        ClearPageWaiters(page);
        /*
         * It's possible to miss clearing Waiters here, when we woke
         * our page waiters, but the hashed waitqueue has waiters for
         * other pages on it.
         *
         * That's okay, it's a rare case. The next waker will clear it.
         */
    }
    spin_unlock_irqrestore(&q->lock, flags);
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

/**
 * read_cache_page - read into page cache, fill it if needed
 * @mapping:    the page's address_space
 * @index:  the page index
 * @filler: function to perform the read
 * @data:   first arg to filler(data, page) function, often left as NULL
 *
 * Read into the page cache. If a page already exists, and PageUptodate() is
 * not set, try to fill the page and wait for it to become unlocked.
 *
 * If the page does not get brought uptodate, return -EIO.
 *
 * Return: up to date page on success, ERR_PTR() on failure.
 */
struct page *read_cache_page(struct address_space *mapping,
                pgoff_t index,
                int (*filler)(void *, struct page *),
                void *data)
{
    /*
    return do_read_cache_page(mapping, index, filler, data,
            mapping_gfp_mask(mapping));
            */
    booter_panic("No impl.");
}

/*
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
*/

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
    int err = 0;

    printk("%s: step1\n", __func__);
    if (mapping_needs_writeback(mapping)) {
        err = __filemap_fdatawrite_range(mapping, lstart, lend,
                         WB_SYNC_ALL);
        /*
         * Even if the above returned error, the pages may be
         * written partially (e.g. -ENOSPC), so we wait for it.
         * But the -EIO is special case, it may indicate the worst
         * thing (e.g. bug) happened, so we avoid waiting for it.
         */
        if (err != -EIO) {
            int err2 = filemap_fdatawait_range(mapping,
                        lstart, lend);
            if (!err)
                err = err2;
        } else {
            /* Clear any previously stored errors */
            filemap_check_errors(mapping);
        }
    } else {
        err = filemap_check_errors(mapping);
    }
    return err;
}

int filemap_check_errors(struct address_space *mapping)
{
    int ret = 0;
    /* Check for outstanding write errors */
    if (test_bit(AS_ENOSPC, &mapping->flags) &&
        test_and_clear_bit(AS_ENOSPC, &mapping->flags))
        ret = -ENOSPC;
    if (test_bit(AS_EIO, &mapping->flags) &&
        test_and_clear_bit(AS_EIO, &mapping->flags))
        ret = -EIO;
    return ret;
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
        printk("%s: isize(%d)\n", __func__, isize);
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
		else {
            printk("%s: Note ===> before lock_page_killable ...\n", __func__);
			error = lock_page_killable(page);
        }
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
			if (iocb->ki_flags & IOCB_WAITQ)
				error = lock_page_async(page, iocb->ki_waitq);
			else {
                printk("%s: Note ===>lock_page_killable ...\n", __func__);
				error = lock_page_killable(page);
            }

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
    printk("%s: written(%d) pos(0x%lx)\n", __func__, written, *ppos);
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
    struct page *page;

repeat:
    page = find_get_entry(mapping, index);
    if (xa_is_value(page))
        page = NULL;
    if (!page)
        goto no_page;

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
        if (unlikely(compound_head(page)->mapping != mapping)) {
            unlock_page(page);
            put_page(page);
            goto repeat;
        }
        VM_BUG_ON_PAGE(page->index != index, page);
    }

    if (fgp_flags & FGP_ACCESSED)
        mark_page_accessed(page);
    else if (fgp_flags & FGP_WRITE) {
        /* Clear idle flag for buffer write */
        if (page_is_idle(page))
            clear_page_idle(page);
    }

no_page:
    if (!page && (fgp_flags & FGP_CREAT)) {
        int err;
        if ((fgp_flags & FGP_WRITE) && mapping_cap_account_dirty(mapping))
            gfp_mask |= __GFP_WRITE;
        if (fgp_flags & FGP_NOFS)
            gfp_mask &= ~__GFP_FS;

        page = __page_cache_alloc(gfp_mask);
        if (!page)
            return NULL;

        if (WARN_ON_ONCE(!(fgp_flags & (FGP_LOCK | FGP_FOR_MMAP))))
            fgp_flags |= FGP_LOCK;

        /* Init accessed so avoid atomic mark_page_accessed later */
        if (fgp_flags & FGP_ACCESSED)
            __SetPageReferenced(page);

        err = add_to_page_cache_lru(page, mapping, index, gfp_mask);
        if (unlikely(err)) {
            put_page(page);
            page = NULL;
            if (err == -EEXIST)
                goto repeat;
        }

        /*
         * add_to_page_cache_lru locks the page, and for mmap we expect
         * an unlocked page.
         */
        if (page && (fgp_flags & FGP_FOR_MMAP))
            unlock_page(page);
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
 * find_get_entries - gang pagecache lookup
 * @mapping:    The address_space to search
 * @start:  The starting page cache index
 * @nr_entries: The maximum number of entries
 * @entries:    Where the resulting entries are placed
 * @indices:    The cache indices corresponding to the entries in @entries
 *
 * find_get_entries() will search for and return a group of up to
 * @nr_entries entries in the mapping.  The entries are placed at
 * @entries.  find_get_entries() takes a reference against any actual
 * pages it returns.
 *
 * The search returns a group of mapping-contiguous page cache entries
 * with ascending indexes.  There may be holes in the indices due to
 * not-present pages.
 *
 * Any shadow entries of evicted pages, or swap entries from
 * shmem/tmpfs, are included in the returned array.
 *
 * If it finds a Transparent Huge Page, head or tail, find_get_entries()
 * stops at that page: the caller is likely to have a better way to handle
 * the compound page as a whole, and then skip its extent, than repeatedly
 * calling find_get_entries() to return all its tails.
 *
 * Return: the number of pages and shadow entries which were found.
 */
unsigned find_get_entries(struct address_space *mapping,
              pgoff_t start, unsigned int nr_entries,
              struct page **entries, pgoff_t *indices)
{
    XA_STATE(xas, &mapping->i_pages, start);
    struct page *page;
    unsigned int ret = 0;

    if (!nr_entries)
        return 0;

    rcu_read_lock();
    xas_for_each(&xas, page, ULONG_MAX) {
        if (xas_retry(&xas, page))
            continue;
        /*
         * A shadow entry of a recently evicted page, a swap
         * entry from shmem/tmpfs or a DAX entry.  Return it
         * without attempting to raise page count.
         */
        if (xa_is_value(page))
            goto export;

        if (!page_cache_get_speculative(page))
            goto retry;

        /* Has the page moved or been split? */
        if (unlikely(page != xas_reload(&xas)))
            goto put_page;

        /*
         * Terminate early on finding a THP, to allow the caller to
         * handle it all at once; but continue if this is hugetlbfs.
         */
        if (PageTransHuge(page) && !PageHuge(page)) {
            page = find_subpage(page, xas.xa_index);
            nr_entries = ret + 1;
        }
export:
        indices[ret] = xas.xa_index;
        entries[ret] = page;
        if (++ret == nr_entries)
            break;
        continue;
put_page:
        put_page(page);
retry:
        xas_reset(&xas);
    }
    rcu_read_unlock();
    return ret;
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

    printk("%s: step1\n", __func__);
    page = pagecache_get_page(mapping, index, fgp_flags,
            mapping_gfp_mask(mapping));
    printk("%s: step2\n", __func__);
    if (page)
        wait_for_stable_page(page);

    return page;
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

        nr_pages = pagevec_lookup_range_tag(&pvec, mapping, &index,
                end, PAGECACHE_TAG_WRITEBACK);
        if (!nr_pages)
            break;

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
 * filemap_fdatawait_range - wait for writeback to complete
 * @mapping:        address space structure to wait for
 * @start_byte:     offset in bytes where the range starts
 * @end_byte:       offset in bytes where the range ends (inclusive)
 *
 * Walk the list of under-writeback pages of the given address space
 * in the given range and wait for all of them.  Check error status of
 * the address space and return it.
 *
 * Since the error status of the address space is cleared by this function,
 * callers are responsible for checking the return value and handling and/or
 * reporting the error.
 *
 * Return: error status of the address space.
 */
int filemap_fdatawait_range(struct address_space *mapping, loff_t start_byte,
                loff_t end_byte)
{
    __filemap_fdatawait_range(mapping, start_byte, end_byte);
    return filemap_check_errors(mapping);
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

static void wake_up_page(struct page *page, int bit)
{
    if (!PageWaiters(page))
        return;
    wake_up_page_bit(page, bit);
}

/**
 * end_page_writeback - end writeback against a page
 * @page: the page
 */
void end_page_writeback(struct page *page)
{
    /*
     * TestClearPageReclaim could be used here but it is an atomic
     * operation and overkill in this particular case. Failing to
     * shuffle a page marked for immediate reclaim is too mild to
     * justify taking an atomic operation penalty at the end of
     * ever page writeback.
     */
    printk("%s: step1\n", __func__);
    if (PageReclaim(page)) {
        ClearPageReclaim(page);
        rotate_reclaimable_page(page);
    }

    printk("%s: step2\n", __func__);
    if (!test_clear_page_writeback(page))
        BUG();

    smp_mb__after_atomic();
    printk("%s: step3\n", __func__);
    wake_up_page(page, PG_writeback);
    printk("%s: stepN\n", __func__);
}

/**
 * try_to_release_page() - release old fs-specific metadata on a page
 *
 * @page: the page which the kernel is trying to free
 * @gfp_mask: memory allocation flags (and I/O mode)
 *
 * The address_space is to try to release any data against the page
 * (presumably at page->private).
 *
 * This may also be called if PG_fscache is set on a page, indicating that the
 * page is known to the local caching routines.
 *
 * The @gfp_mask argument specifies whether I/O may be performed to release
 * this page (__GFP_IO), and whether the call may block (__GFP_RECLAIM & __GFP_FS).
 *
 * Return: %1 if the release was successful, otherwise return zero.
 */
int try_to_release_page(struct page *page, gfp_t gfp_mask)
{
    struct address_space * const mapping = page->mapping;

    BUG_ON(!PageLocked(page));
    if (PageWriteback(page))
        return 0;

    if (mapping && mapping->a_ops->releasepage)
        return mapping->a_ops->releasepage(page, gfp_mask);
    return try_to_free_buffers(page);
}

/*
 * page_cache_delete_batch - delete several pages from page cache
 * @mapping: the mapping to which pages belong
 * @pvec: pagevec with pages to delete
 *
 * The function walks over mapping->i_pages and removes pages passed in @pvec
 * from the mapping. The function expects @pvec to be sorted by page index
 * and is optimised for it to be dense.
 * It tolerates holes in @pvec (mapping entries at those indices are not
 * modified). The function expects only THP head pages to be present in the
 * @pvec.
 *
 * The function expects the i_pages lock to be held.
 */
static void page_cache_delete_batch(struct address_space *mapping,
                 struct pagevec *pvec)
{
    XA_STATE(xas, &mapping->i_pages, pvec->pages[0]->index);
    int total_pages = 0;
    int i = 0;
    struct page *page;

    mapping_set_update(&xas, mapping);
    xas_for_each(&xas, page, ULONG_MAX) {
        if (i >= pagevec_count(pvec))
            break;

        /* A swap/dax/shadow entry got inserted? Skip it. */
        if (xa_is_value(page))
            continue;
        /*
         * A page got inserted in our range? Skip it. We have our
         * pages locked so they are protected from being removed.
         * If we see a page whose index is higher than ours, it
         * means our page has been removed, which shouldn't be
         * possible because we're holding the PageLock.
         */
        if (page != pvec->pages[i]) {
            VM_BUG_ON_PAGE(page->index > pvec->pages[i]->index,
                    page);
            continue;
        }

        WARN_ON_ONCE(!PageLocked(page));

        if (page->index == xas.xa_index)
            page->mapping = NULL;
        /* Leave page->index set: truncation lookup relies on it */

        /*
         * Move to the next page in the vector if this is a regular
         * page or the index is of the last sub-page of this compound
         * page.
         */
        if (page->index + compound_nr(page) - 1 == xas.xa_index)
            i++;
        printk("%s: page(%lx)\n", __func__, page);
        xas_store(&xas, NULL);
        total_pages++;
    }
    mapping->nrpages -= total_pages;
}

static void page_cache_free_page(struct address_space *mapping,
                struct page *page)
{
    void (*freepage)(struct page *);

    freepage = mapping->a_ops->freepage;
    if (freepage)
        freepage(page);

    if (PageTransHuge(page) && !PageHuge(page)) {
        page_ref_sub(page, HPAGE_PMD_NR);
        VM_BUG_ON_PAGE(page_count(page) <= 0, page);
    } else {
        put_page(page);
    }
}

void delete_from_page_cache_batch(struct address_space *mapping,
                  struct pagevec *pvec)
{
    int i;
    unsigned long flags;

    if (!pagevec_count(pvec))
        return;

    xa_lock_irqsave(&mapping->i_pages, flags);

    // Note: consider whether or not to remove this.
    /*
    for (i = 0; i < pagevec_count(pvec); i++) {
        trace_mm_filemap_delete_from_page_cache(pvec->pages[i]);

        unaccount_page_cache_page(mapping, pvec->pages[i]);
    }
    */
    page_cache_delete_batch(mapping, pvec);
    xa_unlock_irqrestore(&mapping->i_pages, flags);

    for (i = 0; i < pagevec_count(pvec); i++)
        page_cache_free_page(mapping, pvec->pages[i]);
}

/*
 * The page wait code treats the "wait->flags" somewhat unusually, because
 * we have multiple different kinds of waits, not just the usual "exclusive"
 * one.
 *
 * We have:
 *
 *  (a) no special bits set:
 *
 *  We're just waiting for the bit to be released, and when a waker
 *  calls the wakeup function, we set WQ_FLAG_WOKEN and wake it up,
 *  and remove it from the wait queue.
 *
 *  Simple and straightforward.
 *
 *  (b) WQ_FLAG_EXCLUSIVE:
 *
 *  The waiter is waiting to get the lock, and only one waiter should
 *  be woken up to avoid any thundering herd behavior. We'll set the
 *  WQ_FLAG_WOKEN bit, wake it up, and remove it from the wait queue.
 *
 *  This is the traditional exclusive wait.
 *
 *  (c) WQ_FLAG_EXCLUSIVE | WQ_FLAG_CUSTOM:
 *
 *  The waiter is waiting to get the bit, and additionally wants the
 *  lock to be transferred to it for fair lock behavior. If the lock
 *  cannot be taken, we stop walking the wait queue without waking
 *  the waiter.
 *
 *  This is the "fair lock handoff" case, and in addition to setting
 *  WQ_FLAG_WOKEN, we set WQ_FLAG_DONE to let the waiter easily see
 *  that it now has the lock.
 */
static int wake_page_function(wait_queue_entry_t *wait, unsigned mode, int sync, void *arg)
{
    unsigned int flags;
    struct wait_page_key *key = arg;
    struct wait_page_queue *wait_page
        = container_of(wait, struct wait_page_queue, wait);

    if (!wake_page_match(wait_page, key))
        return 0;

    /*
     * If it's a lock handoff wait, we get the bit for it, and
     * stop walking (and do not wake it up) if we can't.
     */
    flags = wait->flags;
    if (flags & WQ_FLAG_EXCLUSIVE) {
        if (test_bit(key->bit_nr, &key->page->flags))
            return -1;
        if (flags & WQ_FLAG_CUSTOM) {
            if (test_and_set_bit(key->bit_nr, &key->page->flags))
                return -1;
            flags |= WQ_FLAG_DONE;
        }
    }

    /*
     * We are holding the wait-queue lock, but the waiter that
     * is waiting for this will be checking the flags without
     * any locking.
     *
     * So update the flags atomically, and wake up the waiter
     * afterwards to avoid any races. This store-release pairs
     * with the load-acquire in wait_on_page_bit_common().
     */
    smp_store_release(&wait->flags, flags | WQ_FLAG_WOKEN);
    wake_up_state(wait->private, mode);

    /*
     * Ok, we have successfully done what we're waiting for,
     * and we can unconditionally remove the wait entry.
     *
     * Note that this pairs with the "finish_wait()" in the
     * waiter, and has to be the absolute last thing we do.
     * After this list_del_init(&wait->entry) the wait entry
     * might be de-allocated and the process might even have
     * exited.
     */
    list_del_init_careful(&wait->entry);
    return (flags & WQ_FLAG_EXCLUSIVE) != 0;
}

/* How many times do we accept lock stealing from under a waiter? */
int sysctl_page_lock_unfairness = 5;

static inline int wait_on_page_bit_common(wait_queue_head_t *q,
    struct page *page, int bit_nr, int state, enum behavior behavior)
{
    int unfairness = sysctl_page_lock_unfairness;
    struct wait_page_queue wait_page;
    wait_queue_entry_t *wait = &wait_page.wait;
    bool thrashing = false;
    bool delayacct = false;
    unsigned long pflags;

    printk("%s: ...\n", __func__);
    if (bit_nr == PG_locked &&
        !PageUptodate(page) && PageWorkingset(page)) {
        if (!PageSwapBacked(page)) {
            delayacct_thrashing_start();
            delayacct = true;
        }
        psi_memstall_enter(&pflags);
        thrashing = true;
    }

    init_wait(wait);
    wait->func = wake_page_function;
    wait_page.page = page;
    wait_page.bit_nr = bit_nr;

    printk("%s: step1 q(%lx)\n", __func__, q);
repeat:
    wait->flags = 0;
    if (behavior == EXCLUSIVE) {
        wait->flags = WQ_FLAG_EXCLUSIVE;
        if (--unfairness < 0)
            wait->flags |= WQ_FLAG_CUSTOM;
    }

    /*
     * Do one last check whether we can get the
     * page bit synchronously.
     *
     * Do the SetPageWaiters() marking before that
     * to let any waker we _just_ missed know they
     * need to wake us up (otherwise they'll never
     * even go to the slow case that looks at the
     * page queue), and add ourselves to the wait
     * queue if we need to sleep.
     *
     * This part needs to be done under the queue
     * lock to avoid races.
     */
    spin_lock_irq(&q->lock);
    SetPageWaiters(page);
    printk("%s: step1.1\n", __func__);
    if (!trylock_page_bit_common(page, bit_nr, wait))
        __add_wait_queue_entry_tail(q, wait);
    printk("%s: step1.2\n", __func__);
    spin_unlock_irq(&q->lock);

    printk("%s: step2\n", __func__);
    /*
     * From now on, all the logic will be based on
     * the WQ_FLAG_WOKEN and WQ_FLAG_DONE flag, to
     * see whether the page bit testing has already
     * been done by the wake function.
     *
     * We can drop our reference to the page.
     */
    if (behavior == DROP)
        put_page(page);

    /*
     * Note that until the "finish_wait()", or until
     * we see the WQ_FLAG_WOKEN flag, we need to
     * be very careful with the 'wait->flags', because
     * we may race with a waker that sets them.
     */
    for (;;) {
        unsigned int flags;

        set_current_state(state);

        /* Loop until we've been woken or interrupted */
        flags = smp_load_acquire(&wait->flags);
        if (!(flags & WQ_FLAG_WOKEN)) {
            if (signal_pending_state(state, current))
                break;

            io_schedule();
            continue;
        }

        /* If we were non-exclusive, we're done */
        if (behavior != EXCLUSIVE)
            break;

        /* If the waker got the lock for us, we're done */
        if (flags & WQ_FLAG_DONE)
            break;

        /*
         * Otherwise, if we're getting the lock, we need to
         * try to get it ourselves.
         *
         * And if that fails, we'll have to retry this all.
         */
        if (unlikely(test_and_set_bit(bit_nr, &page->flags)))
            goto repeat;

        wait->flags |= WQ_FLAG_DONE;
        break;
    }

    /*
     * If a signal happened, this 'finish_wait()' may remove the last
     * waiter from the wait-queues, but the PageWaiters bit will remain
     * set. That's ok. The next wakeup will take care of it, and trying
     * to do it here would be difficult and prone to races.
     */
    finish_wait(q, wait);

    if (thrashing) {
        if (delayacct)
            delayacct_thrashing_end();
        psi_memstall_leave(&pflags);
    }

    /*
     * NOTE! The wait->flags weren't stable until we've done the
     * 'finish_wait()', and we could have exited the loop above due
     * to a signal, and had a wakeup event happen after the signal
     * test but before the 'finish_wait()'.
     *
     * So only after the finish_wait() can we reliably determine
     * if we got woken up or not, so we can now figure out the final
     * return value based on that state without races.
     *
     * Also note that WQ_FLAG_WOKEN is sufficient for a non-exclusive
     * waiter, but an exclusive one requires WQ_FLAG_DONE.
     */
    if (behavior == EXCLUSIVE)
        return wait->flags & WQ_FLAG_DONE ? 0 : -EINTR;

    return wait->flags & WQ_FLAG_WOKEN ? 0 : -EINTR;
}

int __lock_page_killable(struct page *__page)
{
    struct page *page = compound_head(__page);
    wait_queue_head_t *q = page_waitqueue(page);
    return wait_on_page_bit_common(q, page, PG_locked, TASK_KILLABLE,
                    EXCLUSIVE);
}

void __init pagecache_init(void)
{
    int i;

    for (i = 0; i < PAGE_WAIT_TABLE_SIZE; i++)
        init_waitqueue_head(&page_wait_table[i]);

    page_writeback_init();
}
