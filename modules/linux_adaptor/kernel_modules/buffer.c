#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/iomap.h>
#include <linux/memcontrol.h>
#include <linux/sched/mm.h>

#include "booter.h"

/*
 * Buffer-head allocation
 */
static struct kmem_cache *bh_cachep __read_mostly;

/*
 * Once the number of bh's in the machine exceeds this level, we start
 * stripping them in writeback.
 */
//static unsigned long max_buffer_heads;

/*
 * Size is a power-of-two in the range 512..PAGE_SIZE,
 * and the case we care about most is PAGE_SIZE.
 *
 * So this *could* possibly be written with those
 * constraints in mind (relevant mostly if some
 * architecture has a slow bit-scan instruction)
 */
static inline int block_size_bits(unsigned int blocksize)
{
    return ilog2(blocksize);
}

static struct buffer_head *create_page_buffers(struct page *page, struct inode *inode, unsigned int b_state)
{
    BUG_ON(!PageLocked(page));

    if (!page_has_buffers(page))
        create_empty_buffers(page, 1 << READ_ONCE(inode->i_blkbits),
                     b_state);
    return page_buffers(page);
}

struct buffer_head *alloc_buffer_head(gfp_t gfp_flags)
{
    struct buffer_head *ret = kmem_cache_zalloc(bh_cachep, gfp_flags);
    if (ret) {
        INIT_LIST_HEAD(&ret->b_assoc_buffers);
        spin_lock_init(&ret->b_uptodate_lock);
        preempt_disable();
        //__this_cpu_inc(bh_accounting.nr);
        //recalc_bh_state();
        preempt_enable();
    }
    return ret;
}

/*
 * We attach and possibly dirty the buffers atomically wrt
 * __set_page_dirty_buffers() via private_lock.  try_to_free_buffers
 * is already excluded via the page lock.
 */
void create_empty_buffers(struct page *page,
            unsigned long blocksize, unsigned long b_state)
{
    struct buffer_head *bh, *head, *tail;

    head = alloc_page_buffers(page, blocksize, true);
    bh = head;
    do {
        bh->b_state |= b_state;
        tail = bh;
        bh = bh->b_this_page;
    } while (bh);
    tail->b_this_page = head;

    spin_lock(&page->mapping->private_lock);
    if (PageUptodate(page) || PageDirty(page)) {
        bh = head;
        do {
            if (PageDirty(page))
                set_buffer_dirty(bh);
            if (PageUptodate(page))
                set_buffer_uptodate(bh);
            bh = bh->b_this_page;
        } while (bh != head);
    }
    attach_page_private(page, head);
    spin_unlock(&page->mapping->private_lock);
}

/*
 * Create the appropriate buffers when given a page for data area and
 * the size of each buffer.. Use the bh->b_this_page linked list to
 * follow the buffers created.  Return NULL if unable to create more
 * buffers.
 *
 * The retry flag is used to differentiate async IO (paging, swapping)
 * which may not fail from ordinary buffer allocations.
 */
struct buffer_head *alloc_page_buffers(struct page *page, unsigned long size,
		bool retry)
{
	struct buffer_head *bh, *head;
	gfp_t gfp = GFP_NOFS | __GFP_ACCOUNT;
	long offset;
	struct mem_cgroup *memcg;

	if (retry)
		gfp |= __GFP_NOFAIL;

	memcg = get_mem_cgroup_from_page(page);
	memalloc_use_memcg(memcg);

	head = NULL;
	offset = PAGE_SIZE;
	while ((offset -= size) >= 0) {
		bh = alloc_buffer_head(gfp);
		if (!bh)
			goto no_grow;

		bh->b_this_page = head;
		bh->b_blocknr = -1;
		head = bh;

		bh->b_size = size;
        printk("%s: -------- %u\n", __func__, bh->b_size);

		/* Link the buffer to its page */
		set_bh_page(bh, page, offset);
	}
out:
	memalloc_unuse_memcg();
	mem_cgroup_put(memcg);
	return head;
/*
 * In case anything failed, we just free everything we got.
 */
no_grow:
	if (head) {
		do {
			bh = head;
			head = head->b_this_page;
			free_buffer_head(bh);
		} while (head);
	}

	goto out;
}

void set_bh_page(struct buffer_head *bh,
        struct page *page, unsigned long offset)
{
    bh->b_page = page;
    BUG_ON(offset >= PAGE_SIZE);
    if (PageHighMem(page))
        /*
         * This catches illegal uses and preserves the offset:
         */
        bh->b_data = (char *)(0 + offset);
    else
        bh->b_data = page_address(page) + offset;
}

static int __block_commit_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to)
{
	unsigned block_start, block_end;
	int partial = 0;
	unsigned blocksize;
	struct buffer_head *bh, *head;

	bh = head = page_buffers(page);
	blocksize = bh->b_size;

	block_start = 0;
	do {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
		} else {
			set_buffer_uptodate(bh);
			mark_buffer_dirty(bh);
		}
		clear_buffer_new(bh);

		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);

	/*
	 * If this is a partial write which happened to make all buffers
	 * uptodate then we can optimize away a bogus readpage() for
	 * the next read(). Here we 'discover' whether the page went
	 * uptodate as a result of this (potentially partial) write.
	 */
	if (!partial)
		SetPageUptodate(page);
	return 0;
}

int block_write_end(struct file *file, struct address_space *mapping,
            loff_t pos, unsigned len, unsigned copied,
            struct page *page, void *fsdata)
{
    struct inode *inode = mapping->host;
    unsigned start;

    start = pos & (PAGE_SIZE - 1);

    if (unlikely(copied < len)) {
        /*
         * The buffers that were written will now be uptodate, so we
         * don't have to worry about a readpage reading them and
         * overwriting a partial write. However if we have encountered
         * a short write and only partially written into a buffer, it
         * will not be marked uptodate, so a readpage might come in and
         * destroy our partial write.
         *
         * Do the simplest thing, and just treat any short write to a
         * non uptodate page as a zero-length write, and force the
         * caller to redo the whole thing.
         */
        if (!PageUptodate(page))
            copied = 0;

        page_zero_new_buffers(page, start+copied, start+len);
    }
    flush_dcache_page(page);

    /* This could be a short (even 0-length) commit */
    __block_commit_write(inode, page, start, start+copied);

    printk("%s: copied(%u)\n", __func__, copied);
    return copied;
}

int generic_write_end(struct file *file, struct address_space *mapping,
            loff_t pos, unsigned len, unsigned copied,
            struct page *page, void *fsdata)
{
    struct inode *inode = mapping->host;
    loff_t old_size = inode->i_size;
    bool i_size_changed = false;

    copied = block_write_end(file, mapping, pos, len, copied, page, fsdata);

    /*
     * No need to use i_size_read() here, the i_size cannot change under us
     * because we hold i_rwsem.
     *
     * But it's important to update i_size while still holding page lock:
     * page writeout could otherwise come in and zero beyond i_size.
     */
    if (pos + copied > inode->i_size) {
        i_size_write(inode, pos + copied);
        i_size_changed = true;
    }

    unlock_page(page);
    put_page(page);

    if (old_size < pos)
        pagecache_isize_extended(inode, old_size, pos);
    /*
     * Don't mark the inode dirty under page lock. First, it unnecessarily
     * makes the holding time of page lock longer. Second, it forces lock
     * ordering of page lock and transaction start for journaling
     * filesystems.
     */
    if (i_size_changed)
        mark_inode_dirty(inode);
    return copied;
}

void mark_buffer_dirty(struct buffer_head *bh)
{
    WARN_ON_ONCE(!buffer_uptodate(bh));

    //trace_block_dirty_buffer(bh);

    /*
     * Very *carefully* optimize the it-is-already-dirty case.
     *
     * Don't let the final "is it dirty" escape to before we
     * perhaps modified the buffer.
     */
    if (buffer_dirty(bh)) {
        smp_mb();
        if (buffer_dirty(bh))
            return;
    }

    if (!test_set_buffer_dirty(bh)) {
        struct page *page = bh->b_page;
        struct address_space *mapping = NULL;

        lock_page_memcg(page);
        if (!TestSetPageDirty(page)) {
            mapping = page_mapping(page);
            if (mapping)
                __set_page_dirty(page, mapping, 0);
        }
        unlock_page_memcg(page);
        if (mapping)
            __mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
    }
}

/*
 * Mark the page dirty, and set it dirty in the page cache, and mark the inode
 * dirty.
 *
 * If warn is true, then emit a warning if the page is not uptodate and has
 * not been truncated.
 *
 * The caller must hold lock_page_memcg().
 */
void __set_page_dirty(struct page *page, struct address_space *mapping,
                 int warn)
{
    unsigned long flags;

    xa_lock_irqsave(&mapping->i_pages, flags);
    if (page->mapping) {    /* Race with truncate? */
        WARN_ON_ONCE(warn && !PageUptodate(page));
        //account_page_dirtied(page, mapping);
        __xa_set_mark(&mapping->i_pages, page_index(page),
                PAGECACHE_TAG_DIRTY);
    }
    xa_unlock_irqrestore(&mapping->i_pages, flags);
}

int sync_dirty_buffer(struct buffer_head *bh)
{
    printk("%s: blknr(%u) b_size(%u)\n",
           __func__, bh->b_blocknr, bh->b_size);

    log_error("%s: No impl.\n", __func__);
}

void __lock_buffer(struct buffer_head *bh)
{
    log_error("%s: No impl.\n", __func__);
}

void unlock_buffer(struct buffer_head *bh)
{
    clear_bit_unlock(BH_Lock, &bh->b_state);
    smp_mb__after_atomic();
    log_error("%s: No impl.\n", __func__);
    //wake_up_bit(&bh->b_state, BH_Lock);
}

/*
 * The generic ->writepage function for buffer-backed address_spaces
 */
int block_write_full_page(struct page *page,
                          get_block_t *get_block,
                          struct writeback_control *wbc)
{
    if (page == NULL || page->mapping == NULL) {
        booter_panic("bad page.");
    }

    struct inode *inode = page->mapping->host;
    if (inode == NULL) {
        booter_panic("bad inode.");
    }
    printk("%s: file len %u\n", __func__, inode->i_size);

    struct buffer_head bh_result;
    memset(&bh_result, 0, sizeof(struct buffer_head));
    bh_result.b_size = PAGE_SIZE;

    // Calculate iblock based on page->index
    sector_t iblock = 0;
    int ret = get_block(inode, iblock, &bh_result, 0);
    if (ret < 0) {
        booter_panic("ext2_get_block error!");
    }

    sector_t blknr = bh_result.b_blocknr * 8;
    printk("%s: blknr %u\n", __func__, blknr);

    if (cl_write_block(blknr, page_to_virt(page), PAGE_SIZE) < 0) {
        booter_panic("write block error!");
    }

    return 0;
}

void __breadahead_gfp(struct block_device *bdev, sector_t block, unsigned size,
              gfp_t gfp)
{
    log_error("No impl.");
}

struct buffer_head *
__getblk_gfp(struct block_device *bdev, sector_t block,
         unsigned size, gfp_t gfp)
{
    return __bread_gfp(bdev, block, size, gfp);
}

void __wait_on_buffer(struct buffer_head * bh)
{
    log_error("%s: impl it.\n", __func__);
    set_buffer_uptodate(bh);
}

/*
 * For a data-integrity writeout, we need to wait upon any in-progress I/O
 * and then start new I/O and then wait upon it.  The caller must have a ref on
 * the buffer_head.
 */
int __sync_dirty_buffer(struct buffer_head *bh, int op_flags)
{
    log_error("%s: impl it.\n", __func__);
    return 0;
}

static void
iomap_to_bh(struct inode *inode, sector_t block, struct buffer_head *bh,
		struct iomap *iomap)
{
	loff_t offset = block << inode->i_blkbits;

	bh->b_bdev = iomap->bdev;

	/*
	 * Block points to offset in file we need to map, iomap contains
	 * the offset at which the map starts. If the map ends before the
	 * current block, then do not map the buffer and let the caller
	 * handle it.
	 */
	BUG_ON(offset >= iomap->offset + iomap->length);

	switch (iomap->type) {
	case IOMAP_HOLE:
		/*
		 * If the buffer is not up to date or beyond the current EOF,
		 * we need to mark it as new to ensure sub-block zeroing is
		 * executed if necessary.
		 */
		if (!buffer_uptodate(bh) ||
		    (offset >= i_size_read(inode)))
			set_buffer_new(bh);
		break;
	case IOMAP_DELALLOC:
		if (!buffer_uptodate(bh) ||
		    (offset >= i_size_read(inode)))
			set_buffer_new(bh);
		set_buffer_uptodate(bh);
		set_buffer_mapped(bh);
		set_buffer_delay(bh);
		break;
	case IOMAP_UNWRITTEN:
		/*
		 * For unwritten regions, we always need to ensure that regions
		 * in the block we are not writing to are zeroed. Mark the
		 * buffer as new to ensure this.
		 */
		set_buffer_new(bh);
		set_buffer_unwritten(bh);
		fallthrough;
	case IOMAP_MAPPED:
		if ((iomap->flags & IOMAP_F_NEW) ||
		    offset >= i_size_read(inode))
			set_buffer_new(bh);
		bh->b_blocknr = (iomap->addr + offset - iomap->offset) >>
				inode->i_blkbits;
		set_buffer_mapped(bh);
		break;
	}
}

int __block_write_begin_int(struct page *page, loff_t pos, unsigned len,
        get_block_t *get_block, struct iomap *iomap)
{
	unsigned from = pos & (PAGE_SIZE - 1);
	unsigned to = from + len;
	struct inode *inode = page->mapping->host;
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize, bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh=wait;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_SIZE);
	BUG_ON(to > PAGE_SIZE);
	BUG_ON(from > to);

	head = create_page_buffers(page, inode, 0);
	blocksize = head->b_size;
	bbits = block_size_bits(blocksize);

	block = (sector_t)page->index << (PAGE_SHIFT - bbits);

	for(bh = head, block_start = 0; bh != head || !block_start;
	    block++, block_start=block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			}
			continue;
		}
		if (buffer_new(bh))
			clear_buffer_new(bh);
		if (!buffer_mapped(bh)) {
			WARN_ON(bh->b_size != blocksize);
			if (get_block) {
				err = get_block(inode, block, bh, 1);
				if (err)
					break;
			} else {
				iomap_to_bh(inode, block, bh, iomap);
			}

			if (buffer_new(bh)) {
				clean_bdev_bh_alias(bh);
				if (PageUptodate(page)) {
					clear_buffer_new(bh);
					set_buffer_uptodate(bh);
					mark_buffer_dirty(bh);
					continue;
				}
				if (block_end > to || block_start < from)
					zero_user_segments(page,
						to, block_end,
						block_start, from);
				continue;
			}
		}
		if (PageUptodate(page)) {
			if (!buffer_uptodate(bh))
				set_buffer_uptodate(bh);
			continue; 
		}
		if (!buffer_uptodate(bh) && !buffer_delay(bh) &&
		    !buffer_unwritten(bh) &&
		     (block_start < from || block_end > to)) {
			ll_rw_block(REQ_OP_READ, 0, 1, &bh);
			*wait_bh++=bh;
		}
	}
	/*
	 * If we issued read requests - let them complete.
	 */
	while(wait_bh > wait) {
		wait_on_buffer(*--wait_bh);
		if (!buffer_uptodate(*wait_bh))
			err = -EIO;
	}
	if (unlikely(err))
		page_zero_new_buffers(page, from, to);
	return err;
}

int __block_write_begin(struct page *page, loff_t pos, unsigned len,
        get_block_t *get_block)
{
    return __block_write_begin_int(page, pos, len, get_block, NULL);
}

void __init buffer_init(void)
{
    unsigned long nrpages;
    int ret;

    bh_cachep = kmem_cache_create("buffer_head",
            sizeof(struct buffer_head), 0,
                (SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|
                SLAB_MEM_SPREAD),
                NULL);

    /*
     * Limit the bh occupancy to 10% of ZONE_NORMAL
     */
    /*
    nrpages = (nr_free_buffer_pages() * 10) / 100;
    max_buffer_heads = nrpages * (PAGE_SIZE / sizeof(struct buffer_head));
    ret = cpuhp_setup_state_nocalls(CPUHP_FS_BUFF_DEAD, "fs/buffer:dead",
                    NULL, buffer_exit_cpu_dead);
    WARN_ON(ret < 0);
    */
}
