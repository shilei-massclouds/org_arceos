#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/export.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/hash.h>
#include <linux/suspend.h>
#include <linux/buffer_head.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/bio.h>
#include <linux/cpu.h>
#include <linux/bitops.h>
#include <linux/mpage.h>
#include <linux/bit_spinlock.h>
#include <linux/pagevec.h>
#include <linux/sched/mm.h>
#include <trace/events/block.h>
#include <linux/fscrypt.h>
#include <linux/fsverity.h>
#include <linux/sched/isolation.h>

#include "internal.h"

#include "../adaptor.h"

#if 0
struct bh_accounting {
    int nr;         /* Number of live bh's */
    int ratelimit;      /* Limit cacheline bouncing */
};

static DEFINE_PER_CPU(struct bh_accounting, bh_accounting) = {0, 0};
#endif

/*
 * Buffer-head allocation
 */
static struct kmem_cache *bh_cachep __ro_after_init;

/*
 * Once the number of bh's in the machine exceeds this level, we start
 * stripping them in writeback.
 */
static unsigned long max_buffer_heads __ro_after_init;

static int buffer_exit_cpu_dead(unsigned int cpu)
{
    PANIC("");
}

/*
 * I/O completion handler for block_read_full_folio() - pages
 * which come unlocked at the end of I/O.
 */
static void end_buffer_async_read_io(struct buffer_head *bh, int uptodate)
{
    PANIC("");
}

static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
    PANIC("");
}

/*
 * If a page's buffers are under async readin (end_buffer_async_read
 * completion) then there is a possibility that another thread of
 * control could lock one of the buffers after it has completed
 * but while some of the other buffers have not completed.  This
 * locked buffer would confuse end_buffer_async_read() into not unlocking
 * the page.  So the absence of BH_Async_Read tells end_buffer_async_read()
 * that this buffer is not under async I/O.
 *
 * The page comes unlocked when it has no locked buffer_async buffers
 * left.
 *
 * PageLocked prevents anyone starting new async I/O reads any of
 * the buffers.
 *
 * PageWriteback is used to prevent simultaneous writeout of the same
 * page.
 *
 * PageLocked prevents anyone from starting writeback of a page which is
 * under read I/O (PageWriteback is only ever set against a locked page).
 */
static void mark_buffer_async_read(struct buffer_head *bh)
{
    bh->b_end_io = end_buffer_async_read_io;
    set_buffer_async_read(bh);
}

static struct buffer_head *folio_create_buffers(struct folio *folio,
                        struct inode *inode,
                        unsigned int b_state)
{
    struct buffer_head *bh;

    BUG_ON(!folio_test_locked(folio));

    bh = folio_buffers(folio);
    if (!bh)
        bh = create_empty_buffers(folio,
                1 << READ_ONCE(inode->i_blkbits), b_state);
    return bh;
}

/*
 * Generic "read_folio" function for block devices that have the normal
 * get_block functionality. This is most of the block device filesystems.
 * Reads the folio asynchronously --- the unlock_buffer() and
 * set/clear_buffer_uptodate() functions propagate buffer state into the
 * folio once IO has completed.
 */
int block_read_full_folio(struct folio *folio, get_block_t *get_block)
{
    struct inode *inode = folio->mapping->host;
    sector_t iblock, lblock;
    struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
    size_t blocksize;
    int nr, i;
    int fully_mapped = 1;
    bool page_error = false;
    loff_t limit = i_size_read(inode);

    /* This is needed for ext4. */
    if (IS_ENABLED(CONFIG_FS_VERITY) && IS_VERITY(inode))
        limit = inode->i_sb->s_maxbytes;

    VM_BUG_ON_FOLIO(folio_test_large(folio), folio);

    head = folio_create_buffers(folio, inode, 0);
    blocksize = head->b_size;

    iblock = div_u64(folio_pos(folio), blocksize);
    lblock = div_u64(limit + blocksize - 1, blocksize);
    bh = head;
    nr = 0;
    i = 0;

    do {
        if (buffer_uptodate(bh))
            continue;

        if (!buffer_mapped(bh)) {
            int err = 0;

            fully_mapped = 0;
            if (iblock < lblock) {
                WARN_ON(bh->b_size != blocksize);
                err = get_block(inode, iblock, bh, 0);
                if (err)
                    page_error = true;
            }
            if (!buffer_mapped(bh)) {
                folio_zero_range(folio, i * blocksize,
                        blocksize);
                if (!err)
                    set_buffer_uptodate(bh);
                continue;
            }
            /*
             * get_block() might have updated the buffer
             * synchronously
             */
            if (buffer_uptodate(bh))
                continue;
        }
        arr[nr++] = bh;
    } while (i++, iblock++, (bh = bh->b_this_page) != head);

    if (fully_mapped)
        folio_set_mappedtodisk(folio);

    if (!nr) {
        /*
         * All buffers are uptodate or get_block() returned an
         * error when trying to map them - we can finish the read.
         */
        folio_end_read(folio, !page_error);
        return 0;
    }

    /* Stage two: lock the buffers */
    for (i = 0; i < nr; i++) {
        bh = arr[i];
        lock_buffer(bh);
        mark_buffer_async_read(bh);
    }

    /*
     * Stage 3: start the IO.  Check for uptodateness
     * inside the buffer lock in case another process reading
     * the underlying blockdev brought it uptodate (the sct fix).
     */
    for (i = 0; i < nr; i++) {
        bh = arr[i];
        if (buffer_uptodate(bh))
            end_buffer_async_read(bh, 1);
        else
            submit_bh(REQ_OP_READ, bh);
    }

    PANIC("");
    return 0;
}

/*
 * We attach and possibly dirty the buffers atomically wrt
 * block_dirty_folio() via i_private_lock.  try_to_free_buffers
 * is already excluded via the folio lock.
 */
struct buffer_head *create_empty_buffers(struct folio *folio,
        unsigned long blocksize, unsigned long b_state)
{
    struct buffer_head *bh, *head, *tail;
    gfp_t gfp = GFP_NOFS | __GFP_ACCOUNT | __GFP_NOFAIL;

    head = folio_alloc_buffers(folio, blocksize, gfp);
    bh = head;
    do {
        bh->b_state |= b_state;
        tail = bh;
        bh = bh->b_this_page;
    } while (bh);
    tail->b_this_page = head;

    spin_lock(&folio->mapping->i_private_lock);
    if (folio_test_uptodate(folio) || folio_test_dirty(folio)) {
        bh = head;
        do {
            if (folio_test_dirty(folio))
                set_buffer_dirty(bh);
            if (folio_test_uptodate(folio))
                set_buffer_uptodate(bh);
            bh = bh->b_this_page;
        } while (bh != head);
    }
    folio_attach_private(folio, head);
    spin_unlock(&folio->mapping->i_private_lock);

    return head;
}

void folio_set_bh(struct buffer_head *bh, struct folio *folio,
          unsigned long offset)
{
    bh->b_folio = folio;
    BUG_ON(offset >= folio_size(folio));
    if (folio_test_highmem(folio))
        /*
         * This catches illegal uses and preserves the offset:
         */
        bh->b_data = (char *)(0 + offset);
    else
        bh->b_data = folio_address(folio) + offset;
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

void free_buffer_head(struct buffer_head *bh)
{
    BUG_ON(!list_empty(&bh->b_assoc_buffers));
    kmem_cache_free(bh_cachep, bh);
    preempt_disable();
    //__this_cpu_dec(bh_accounting.nr);
    //recalc_bh_state();
    preempt_enable();
}

/*
 * Create the appropriate buffers when given a folio for data area and
 * the size of each buffer.. Use the bh->b_this_page linked list to
 * follow the buffers created.  Return NULL if unable to create more
 * buffers.
 *
 * The retry flag is used to differentiate async IO (paging, swapping)
 * which may not fail from ordinary buffer allocations.
 */
struct buffer_head *folio_alloc_buffers(struct folio *folio, unsigned long size,
                    gfp_t gfp)
{
    struct buffer_head *bh, *head;
    long offset;
#if 0
    struct mem_cgroup *memcg, *old_memcg;

    /* The folio lock pins the memcg */
    memcg = folio_memcg(folio);
    old_memcg = set_active_memcg(memcg);
#endif

    head = NULL;
    offset = folio_size(folio);
    while ((offset -= size) >= 0) {
        bh = alloc_buffer_head(gfp);
        if (!bh)
            goto no_grow;

        bh->b_this_page = head;
        bh->b_blocknr = -1;
        head = bh;

        bh->b_size = size;

        /* Link the buffer to its folio */
        folio_set_bh(bh, folio, offset);
    }
out:
    //set_active_memcg(old_memcg);
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

static void end_bio_bh_io_sync(struct bio *bio)
{
    struct buffer_head *bh = bio->bi_private;

    if (unlikely(bio_flagged(bio, BIO_QUIET)))
        set_bit(BH_Quiet, &bh->b_state);

    bh->b_end_io(bh, !bio->bi_status);
    bio_put(bio);
}

static void submit_bh_wbc(blk_opf_t opf, struct buffer_head *bh,
              enum rw_hint write_hint,
              struct writeback_control *wbc)
{
    const enum req_op op = opf & REQ_OP_MASK;
    struct bio *bio;

    BUG_ON(!buffer_locked(bh));
    BUG_ON(!buffer_mapped(bh));
    BUG_ON(!bh->b_end_io);
    BUG_ON(buffer_delay(bh));
    BUG_ON(buffer_unwritten(bh));

    /*
     * Only clear out a write error when rewriting
     */
    if (test_set_buffer_req(bh) && (op == REQ_OP_WRITE))
        clear_buffer_write_io_error(bh);

    if (buffer_meta(bh))
        opf |= REQ_META;
    if (buffer_prio(bh))
        opf |= REQ_PRIO;

    printk("%s: step1\n", __func__);
    bio = bio_alloc(bh->b_bdev, 1, opf, GFP_NOIO);

    fscrypt_set_bio_crypt_ctx_bh(bio, bh, GFP_NOIO);

    bio->bi_iter.bi_sector = bh->b_blocknr * (bh->b_size >> 9);
    bio->bi_write_hint = write_hint;

    bio_add_folio_nofail(bio, bh->b_folio, bh->b_size, bh_offset(bh));

    bio->bi_end_io = end_bio_bh_io_sync;
    bio->bi_private = bh;

    /* Take care of bh's that straddle the end of the device */
    guard_bio_eod(bio);

    printk("%s: step2\n", __func__);
    if (wbc) {
        wbc_init_bio(wbc, bio);
        wbc_account_cgroup_owner(wbc, bh->b_folio, bh->b_size);
    }

    submit_bio(bio);
}

void submit_bh(blk_opf_t opf, struct buffer_head *bh)
{
    submit_bh_wbc(opf, bh, WRITE_LIFE_NOT_SET, NULL);
}

void __init buffer_init(void)
{
    unsigned long nrpages;
    int ret;

    bh_cachep = KMEM_CACHE(buffer_head,
                SLAB_RECLAIM_ACCOUNT|SLAB_PANIC);
#if 0
    /*
     * Limit the bh occupancy to 10% of ZONE_NORMAL
     */
    nrpages = (nr_free_buffer_pages() * 10) / 100;
    max_buffer_heads = nrpages * (PAGE_SIZE / sizeof(struct buffer_head));
    ret = cpuhp_setup_state_nocalls(CPUHP_FS_BUFF_DEAD, "fs/buffer:dead",
                    NULL, buffer_exit_cpu_dead);
    WARN_ON(ret < 0);
#endif
}
