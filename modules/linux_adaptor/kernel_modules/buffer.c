#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/iomap.h>
#include <linux/memcontrol.h>
#include <linux/sched/mm.h>

#include "booter.h"

/*
 * Called when truncating a buffer on a page completely.
 */

/* Bits that are cleared during an invalidate */
#define BUFFER_FLAGS_DISCARD \
    (1 << BH_Mapped | 1 << BH_New | 1 << BH_Req | \
     1 << BH_Delay | 1 << BH_Unwritten)

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

static void buffer_io_error(struct buffer_head *bh, char *msg)
{
    if (!test_bit(BH_Quiet, &bh->b_state))
        printk_ratelimited(KERN_ERR
            "Buffer I/O error on dev %pg, logical block %llu%s\n",
            bh->b_bdev, (unsigned long long)bh->b_blocknr, msg);
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
	printk("%s: step1 (%lx)\n", __func__, mapping->host);
        if (mapping)
            __mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
	printk("%s: step2\n", __func__);
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
    wait_on_bit_lock_io(&bh->b_state, BH_Lock, TASK_UNINTERRUPTIBLE);
}

void unlock_buffer(struct buffer_head *bh)
{
    clear_bit_unlock(BH_Lock, &bh->b_state);
    smp_mb__after_atomic();
    wake_up_bit(&bh->b_state, BH_Lock);
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

static sector_t blkdev_max_block(struct block_device *bdev, unsigned int size)
{
    printk("%s: ...\n", __func__);
    sector_t retval = ~((sector_t)0);
    loff_t sz = i_size_read(bdev->bd_inode);
    printk("%s: sz(%u)\n", __func__, sz);

    if (sz) {
        unsigned int sizebits = blksize_bits(size);
        retval = (sz >> sizebits);
    }
    return retval;
}

/*
 * Initialise the state of a blockdev page's buffers.
 */
static sector_t
init_page_buffers(struct page *page, struct block_device *bdev,
            sector_t block, int size)
{
    printk("%s: ...\n", __func__);
    struct buffer_head *head = page_buffers(page);
    struct buffer_head *bh = head;
    int uptodate = PageUptodate(page);
    sector_t end_block = blkdev_max_block(I_BDEV(bdev->bd_inode), size);

    printk("%s: end_block(%x)\n", __func__, end_block);
    do {
        if (!buffer_mapped(bh)) {
            bh->b_end_io = NULL;
            bh->b_private = NULL;
            bh->b_bdev = bdev;
            bh->b_blocknr = block;
            if (uptodate)
                set_buffer_uptodate(bh);
            if (block < end_block)
                set_buffer_mapped(bh);
        }
        block++;
        bh = bh->b_this_page;
    } while (bh != head);

    /*
     * Caller needs to validate requested block against end of device.
     */
    return end_block;
}

static inline void
link_dev_buffers(struct page *page, struct buffer_head *head)
{
    struct buffer_head *bh, *tail;

    bh = head;
    do {
        tail = bh;
        bh = bh->b_this_page;
    } while (bh);
    tail->b_this_page = head;
    attach_page_private(page, head);
}

/*
 * Create the page-cache page that contains the requested block.
 *
 * This is used purely for blockdev mappings.
 */
static int
grow_dev_page(struct block_device *bdev, sector_t block,
          pgoff_t index, int size, int sizebits, gfp_t gfp)
{
    struct inode *inode = bdev->bd_inode;
    struct page *page;
    struct buffer_head *bh;
    sector_t end_block;
    int ret = 0;
    gfp_t gfp_mask;

    gfp_mask = mapping_gfp_constraint(inode->i_mapping, ~__GFP_FS) | gfp;

    /*
     * XXX: __getblk_slow() can not really deal with failure and
     * will endlessly loop on improvised global reclaim.  Prefer
     * looping in the allocator rather than here, at least that
     * code knows what it's doing.
     */
    gfp_mask |= __GFP_NOFAIL;

    printk("%s: blknr(%u) index(%u) size(%u) sizebits(%u)\n",
           __func__, block, index, size, sizebits);

    page = find_or_create_page(inode->i_mapping, index, gfp_mask);

    BUG_ON(!PageLocked(page));

    if (page_has_buffers(page)) {
        bh = page_buffers(page);
        if (bh->b_size == size) {
            end_block = init_page_buffers(page, bdev,
                        (sector_t)index << sizebits,
                        size);
            goto done;
        }
        if (!try_to_free_buffers(page))
            goto failed;
    }

    /*
     * Allocate some buffers for this page
     */
    bh = alloc_page_buffers(page, size, true);

    /*
     * Link the page to the buffers and initialise them.  Take the
     * lock to be atomic wrt __find_get_block(), which does not
     * run under the page lock.
     */
    spin_lock(&inode->i_mapping->private_lock);
    link_dev_buffers(page, bh);
    end_block = init_page_buffers(page, bdev, (sector_t)index << sizebits,
            size);
    spin_unlock(&inode->i_mapping->private_lock);
done:
    ret = (block < end_block) ? 1 : -ENXIO;
failed:
    unlock_page(page);
    put_page(page);
    return ret;
}

/*
 * Create buffers for the specified block device block's page.  If
 * that page was dirty, the buffers are set dirty also.
 */
static int
grow_buffers(struct block_device *bdev, sector_t block, int size, gfp_t gfp)
{
    pgoff_t index;
    int sizebits;

    sizebits = -1;
    do {
        sizebits++;
    } while ((size << sizebits) < PAGE_SIZE);

    index = block >> sizebits;

    /*
     * Check for a block which wants to lie outside our maximum possible
     * pagecache index.  (this comparison is done using sector_t types).
     */
    if (unlikely(index != block >> sizebits)) {
        printk(KERN_ERR "%s: requested out-of-range block %llu for "
            "device %pg\n",
            __func__, (unsigned long long)block,
            bdev);
        return -EIO;
    }

    printk("%s: blknr(%u) index(%u)\n", __func__, block, index);
    /* Create a page with the proper size buffers.. */
    return grow_dev_page(bdev, block, index, size, sizebits, gfp);
}

static struct buffer_head *
__getblk_slow(struct block_device *bdev, sector_t block,
         unsigned size, gfp_t gfp)
{
    printk("%s: blocknr(%lx) size(%u)\n", __func__, block, size);

    /* Size must be multiple of hard sectorsize */
    if (unlikely(size & (bdev_logical_block_size(bdev)-1) ||
            (size < 512 || size > PAGE_SIZE))) {
        printk(KERN_ERR "getblk(): invalid block size %d requested\n",
                    size);
        printk(KERN_ERR "logical block size: %d\n",
                    bdev_logical_block_size(bdev));

        dump_stack();
        return NULL;
    }

    for (;;) {
        struct buffer_head *bh;
        int ret;

    printk("%s: 2 block(%u) size(%u)\n", __func__, block, size);
        bh = __find_get_block(bdev, block, size);
        if (bh)
            return bh;

    printk("%s: 3 block(%u) size(%u)\n", __func__, block, size);
        ret = grow_buffers(bdev, block, size, gfp);
        if (ret < 0)
            return NULL;
    }
}

/*
 * Look up the bh in this cpu's LRU.  If it's there, move it to the head.
 */
static struct buffer_head *
lookup_bh_lru(struct block_device *bdev, sector_t block, unsigned size)
{
    // Note: impl it.
    return NULL;
}

/*
 * Install a buffer_head into this cpu's LRU.  If not already in the LRU, it is
 * inserted at the front, and the buffer_head at the back if any is evicted.
 * Or, if already in the LRU it is moved to the front.
 */
static void bh_lru_install(struct buffer_head *bh)
{
    // Note: impl it.
}

/*
 * Various filesystems appear to want __find_get_block to be non-blocking.
 * But it's the page lock which protects the buffers.  To get around this,
 * we get exclusion from try_to_free_buffers with the blockdev mapping's
 * private_lock.
 *
 * Hack idea: for the blockdev mapping, private_lock contention
 * may be quite high.  This code could TryLock the page, and if that
 * succeeds, there is no need to take private_lock.
 */
static struct buffer_head *
__find_get_block_slow(struct block_device *bdev, sector_t block)
{
    printk("%s: ... blknr(%u)\n", __func__, block);
    struct inode *bd_inode = bdev->bd_inode;
    struct address_space *bd_mapping = bd_inode->i_mapping;
    struct buffer_head *ret = NULL;
    pgoff_t index;
    struct buffer_head *bh;
    struct buffer_head *head;
    struct page *page;
    int all_mapped = 1;
    static DEFINE_RATELIMIT_STATE(last_warned, HZ, 1);

    index = block >> (PAGE_SHIFT - bd_inode->i_blkbits);
    page = find_get_page_flags(bd_mapping, index, FGP_ACCESSED);
    if (!page)
        goto out;

    spin_lock(&bd_mapping->private_lock);
    if (!page_has_buffers(page))
        goto out_unlock;
    head = page_buffers(page);
    bh = head;
    do {
        if (!buffer_mapped(bh))
            all_mapped = 0;
        else if (bh->b_blocknr == block) {
            ret = bh;
            get_bh(bh);
            goto out_unlock;
        }
        bh = bh->b_this_page;
    } while (bh != head);

    booter_panic("No impl.");

out_unlock:
    spin_unlock(&bd_mapping->private_lock);
    put_page(page);
out:
    printk("%s: End.\n", __func__);
    return ret;
}

/*
 * Perform a pagecache lookup for the matching buffer.  If it's there, refresh
 * it in the LRU and mark it as accessed.  If it is not present then return
 * NULL
 */
struct buffer_head *
__find_get_block(struct block_device *bdev, sector_t block, unsigned size)
{
    struct buffer_head *bh = lookup_bh_lru(bdev, block, size);

    printk("%s: ... blknr(%u) size(%u)\n", __func__, block, size);
    if (bh == NULL) {
        /* __find_get_block_slow will mark the page accessed */
        bh = __find_get_block_slow(bdev, block);
        if (bh)
            bh_lru_install(bh);
    } else
        touch_buffer(bh);

    return bh;
}

/*
 * __getblk_gfp() will locate (and, if necessary, create) the buffer_head
 * which corresponds to the passed block_device, block and size. The
 * returned buffer has its reference count incremented.
 *
 * __getblk_gfp() will lock up the machine if grow_dev_page's
 * try_to_free_buffers() attempt is failing.  FIXME, perhaps?
 */
struct buffer_head *
__getblk_gfp(struct block_device *bdev, sector_t block,
         unsigned size, gfp_t gfp)
{
    printk("%s: block(%u) size(%u)\n", __func__, block, size);
    struct buffer_head *bh = __find_get_block(bdev, block, size);
    if (bh) {
        printk("%s: bhsize(%u)\n", __func__, bh->b_size);
    }

    might_sleep();
    if (bh == NULL)
        bh = __getblk_slow(bdev, block, size, gfp);
    return bh;
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

/*
struct buffer_head *
__bread_gfp(struct block_device *bdev, sector_t block,
           unsigned size, gfp_t gfp)
{
    printk("%s: blknr(%llu) size(%u) BLOCK_SIZE(%u)\n",
           __func__, block, size, BLOCK_SIZE);

    int blkid;
    int offset;
    if (size == 4096) {
        blkid = block * 8;
        offset = 0;
    } else {
        blkid = block * 2;
        offset = 0;
    }

    void *buf = alloc_pages_exact(4096, 0);
    cl_read_block(blkid, buf, 4096);

    struct buffer_head *bh = kmalloc(sizeof(struct buffer_head), 0);
    bh->b_data = buf + offset;
    bh->b_size = 4096;
    bh->b_blocknr = block;
    bh->b_page = virt_to_page(buf);
    bh->b_bdev = bdev;
    set_buffer_uptodate(bh);
    return bh;
}
*/

static struct buffer_head *__bread_slow(struct buffer_head *bh)
{
    lock_buffer(bh);
    if (buffer_uptodate(bh)) {
        unlock_buffer(bh);
        return bh;
    } else {
        get_bh(bh);
        bh->b_end_io = end_buffer_read_sync;
        submit_bh(REQ_OP_READ, 0, bh);
        wait_on_buffer(bh);
        if (buffer_uptodate(bh))
            return bh;
    }
    brelse(bh);
    return NULL;
}

/**
 *  __bread_gfp() - reads a specified block and returns the bh
 *  @bdev: the block_device to read from
 *  @block: number of block
 *  @size: size (in bytes) to read
 *  @gfp: page allocation flag
 *
 *  Reads a specified block, and returns buffer head that contains it.
 *  The page cache can be allocated from non-movable area
 *  not to prevent page migration if you set gfp to zero.
 *  It returns NULL if the block was unreadable.
 */
struct buffer_head *
__bread_gfp(struct block_device *bdev, sector_t block,
           unsigned size, gfp_t gfp)
{
    printk("%s: ... blknr(%u) size(%u)\n", __func__, block, size);
    struct buffer_head *bh = __getblk_gfp(bdev, block, size, gfp);

    printk("%s: block(%u) size(%u) bh(0x%lx)\n", __func__, block, size, bh);
    if (likely(bh) && !buffer_uptodate(bh))
        bh = __bread_slow(bh);
    return bh;
}

/*
 * End-of-IO handler helper function which does not touch the bh after
 * unlocking it.
 * Note: unlock_buffer() sort-of does touch the bh after unlocking it, but
 * a race there is benign: unlock_buffer() only use the bh's address for
 * hashing after unlocking the buffer, so it doesn't actually touch the bh
 * itself.
 */
static void __end_buffer_read_notouch(struct buffer_head *bh, int uptodate)
{
    printk("%s: ...\n", __func__);
    if (uptodate) {
        set_buffer_uptodate(bh);
    } else {
        /* This happens, due to failed read-ahead attempts. */
        clear_buffer_uptodate(bh);
    }
    unlock_buffer(bh);
}

/*
 * Default synchronous end-of-IO handler..  Just mark it up-to-date and
 * unlock the buffer. This is what ll_rw_block uses too.
 */
void end_buffer_read_sync(struct buffer_head *bh, int uptodate)
{
    printk("%s: ...\n", __func__);
    __end_buffer_read_notouch(bh, uptodate);
    put_bh(bh);
}

void invalidate_bh_lrus(void)
{
    log_error("%s: No impl.\n", __func__);
    //on_each_cpu_cond(has_bh_in_lru, invalidate_bh_lru, NULL, 1);
}

static void discard_buffer(struct buffer_head * bh)
{
    unsigned long b_state, b_state_old;

    lock_buffer(bh);
    clear_buffer_dirty(bh);
    bh->b_bdev = NULL;
    b_state = bh->b_state;
    for (;;) {
        b_state_old = cmpxchg(&bh->b_state, b_state,
                      (b_state & ~BUFFER_FLAGS_DISCARD));
        if (b_state_old == b_state)
            break;
        b_state = b_state_old;
    }
    unlock_buffer(bh);
}

/**
 * block_invalidatepage - invalidate part or all of a buffer-backed page
 *
 * @page: the page which is affected
 * @offset: start of the range to invalidate
 * @length: length of the range to invalidate
 *
 * block_invalidatepage() is called when all or part of the page has become
 * invalidated by a truncate operation.
 *
 * block_invalidatepage() does not have to release all buffers, but it must
 * ensure that no dirty buffer is left outside @offset and that no I/O
 * is underway against any of the blocks which are outside the truncation
 * point.  Because the caller is about to free (and possibly reuse) those
 * blocks on-disk.
 */
void block_invalidatepage(struct page *page, unsigned int offset,
              unsigned int length)
{
    struct buffer_head *head, *bh, *next;
    unsigned int curr_off = 0;
    unsigned int stop = length + offset;

    BUG_ON(!PageLocked(page));
    if (!page_has_buffers(page))
        goto out;

    /*
     * Check for overflow
     */
    BUG_ON(stop > PAGE_SIZE || stop < length);

    head = page_buffers(page);
    bh = head;
    do {
        unsigned int next_off = curr_off + bh->b_size;
        next = bh->b_this_page;

        /*
         * Are we still fully in range ?
         */
        if (next_off > stop)
            goto out;

        /*
         * is this block fully invalidated?
         */
        if (offset <= curr_off)
            discard_buffer(bh);
        curr_off = next_off;
        bh = next;
    } while (bh != head);

    /*
     * We release buffers only if the entire page is being invalidated.
     * The get_block cached value has been unconditionally invalidated,
     * so real IO is not possible anymore.
     */
    if (length == PAGE_SIZE)
        try_to_release_page(page, 0);
out:
    return;
}

/*
 * The buffer's backing address_space's private_lock must be held
 */
static void __remove_assoc_queue(struct buffer_head *bh)
{
    list_del_init(&bh->b_assoc_buffers);
    WARN_ON(!bh->b_assoc_map);
    bh->b_assoc_map = NULL;
}

/*
 * try_to_free_buffers() checks if all the buffers on this particular page
 * are unused, and releases them if so.
 *
 * Exclusion against try_to_free_buffers may be obtained by either
 * locking the page or by holding its mapping's private_lock.
 *
 * If the page is dirty but all the buffers are clean then we need to
 * be sure to mark the page clean as well.  This is because the page
 * may be against a block device, and a later reattachment of buffers
 * to a dirty page will set *all* buffers dirty.  Which would corrupt
 * filesystem data on the same device.
 *
 * The same applies to regular filesystem pages: if all the buffers are
 * clean then we set the page clean and proceed.  To do that, we require
 * total exclusion from __set_page_dirty_buffers().  That is obtained with
 * private_lock.
 *
 * try_to_free_buffers() is non-blocking.
 */
static inline int buffer_busy(struct buffer_head *bh)
{
    return atomic_read(&bh->b_count) |
        (bh->b_state & ((1 << BH_Dirty) | (1 << BH_Lock)));
}

static int
drop_buffers(struct page *page, struct buffer_head **buffers_to_free)
{
    struct buffer_head *head = page_buffers(page);
    struct buffer_head *bh;

    bh = head;
    do {
        if (buffer_busy(bh))
            goto failed;
        bh = bh->b_this_page;
    } while (bh != head);

    do {
        struct buffer_head *next = bh->b_this_page;

        if (bh->b_assoc_map)
            __remove_assoc_queue(bh);
        bh = next;
    } while (bh != head);
    *buffers_to_free = head;
    detach_page_private(page);
    return 1;
failed:
    return 0;
}

int try_to_free_buffers(struct page *page)
{
    struct address_space * const mapping = page->mapping;
    struct buffer_head *buffers_to_free = NULL;
    int ret = 0;

    BUG_ON(!PageLocked(page));
    if (PageWriteback(page))
        return 0;

    if (mapping == NULL) {      /* can this still happen? */
        ret = drop_buffers(page, &buffers_to_free);
        goto out;
    }

    spin_lock(&mapping->private_lock);
    ret = drop_buffers(page, &buffers_to_free);

    /*
     * If the filesystem writes its buffers by hand (eg ext3)
     * then we can have clean buffers against a dirty page.  We
     * clean the page here; otherwise the VM will never notice
     * that the filesystem did any IO at all.
     *
     * Also, during truncate, discard_buffer will have marked all
     * the page's buffers clean.  We discover that here and clean
     * the page also.
     *
     * private_lock must be held over this entire operation in order
     * to synchronise against __set_page_dirty_buffers and prevent the
     * dirty bit from being lost.
     */
    if (ret)
        cancel_dirty_page(page);
    spin_unlock(&mapping->private_lock);
out:
    if (buffers_to_free) {
        struct buffer_head *bh = buffers_to_free;

        do {
            struct buffer_head *next = bh->b_this_page;
            free_buffer_head(bh);
            bh = next;
        } while (bh != buffers_to_free);
    }
    return ret;
}

void end_buffer_write_sync(struct buffer_head *bh, int uptodate)
{
    printk("%s: ...\n", __func__);
    if (uptodate) {
        set_buffer_uptodate(bh);
    } else {
        buffer_io_error(bh, ", lost sync page write");
        mark_buffer_write_io_error(bh);
        clear_buffer_uptodate(bh);
    }
    unlock_buffer(bh);
    put_bh(bh);
}

void mark_buffer_write_io_error(struct buffer_head *bh)
{
    struct super_block *sb;

    set_buffer_write_io_error(bh);
    /* FIXME: do we need to set this in both places? */
    if (bh->b_page && bh->b_page->mapping)
        mapping_set_error(bh->b_page->mapping, -EIO);
    if (bh->b_assoc_map)
        mapping_set_error(bh->b_assoc_map, -EIO);
    rcu_read_lock();
    sb = READ_ONCE(bh->b_bdev->bd_super);
    if (sb)
        errseq_set(&sb->s_wb_err, -EIO);
    rcu_read_unlock();
}

void free_buffer_head(struct buffer_head *bh)
{
    log_error("%s: No impl.\n", __func__);
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
