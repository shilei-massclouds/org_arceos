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

#define BH_LRU_SIZE 16

struct bh_lru {
    struct buffer_head *bhs[BH_LRU_SIZE];
};

static DEFINE_PER_CPU(struct bh_lru, bh_lrus) = {{ NULL }};

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

#ifdef CONFIG_SMP
#define bh_lru_lock()   local_irq_disable()
#define bh_lru_unlock() local_irq_enable()
#else
#define bh_lru_lock()   preempt_disable()
#define bh_lru_unlock() preempt_enable()
#endif

static inline void check_irqs_on(void)
{
#ifdef irqs_disabled
    BUG_ON(irqs_disabled());
#endif
}

bool has_bh_in_lru(int cpu, void *dummy)
{
    struct bh_lru *b = per_cpu_ptr(&bh_lrus, cpu);
    int i;

    for (i = 0; i < BH_LRU_SIZE; i++) {
        if (b->bhs[i])
            return true;
    }

    return false;
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
    if (uptodate) {
        set_buffer_uptodate(bh);
    } else {
        /* This happens, due to failed read-ahead attempts. */
        clear_buffer_uptodate(bh);
    }
    unlock_buffer(bh);
}

/**
 * __brelse - Release a buffer.
 * @bh: The buffer to release.
 *
 * This variant of brelse() can be called if @bh is guaranteed to not be NULL.
 */
void __brelse(struct buffer_head *bh)
{
    if (atomic_read(&bh->b_count)) {
        put_bh(bh);
        return;
    }
    WARN(1, KERN_ERR "VFS: brelse: Trying to free free buffer\n");
}
/*
 * Default synchronous end-of-IO handler..  Just mark it up-to-date and
 * unlock the buffer.
 */
void end_buffer_read_sync(struct buffer_head *bh, int uptodate)
{
    printk("%s: step1\n", __func__);
    __end_buffer_read_notouch(bh, uptodate);
    put_bh(bh);
}

void unlock_buffer(struct buffer_head *bh)
{
    clear_bit_unlock(BH_Lock, &bh->b_state);
    smp_mb__after_atomic();
    wake_up_bit(&bh->b_state, BH_Lock);
}

static int buffer_exit_cpu_dead(unsigned int cpu)
{
    PANIC("");
}

static bool need_fsverity(struct buffer_head *bh)
{
    struct folio *folio = bh->b_folio;
    struct inode *inode = folio->mapping->host;

    return fsverity_active(inode) &&
        /* needed by ext4 */
        folio->index < DIV_ROUND_UP(inode->i_size, PAGE_SIZE);
}

static void buffer_io_error(struct buffer_head *bh, char *msg)
{
    if (!test_bit(BH_Quiet, &bh->b_state))
        printk_ratelimited(KERN_ERR
            "Buffer I/O error on dev %pg, logical block %llu%s\n",
            bh->b_bdev, (unsigned long long)bh->b_blocknr, msg);
}

static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
    unsigned long flags;
    struct buffer_head *first;
    struct buffer_head *tmp;
    struct folio *folio;
    int folio_uptodate = 1;

    BUG_ON(!buffer_async_read(bh));

    folio = bh->b_folio;
    if (uptodate) {
        set_buffer_uptodate(bh);
    } else {
        clear_buffer_uptodate(bh);
        buffer_io_error(bh, ", async page read");
    }

    /*
     * Be _very_ careful from here on. Bad things can happen if
     * two buffer heads end IO at almost the same time and both
     * decide that the page is now completely done.
     */
    first = folio_buffers(folio);
    spin_lock_irqsave(&first->b_uptodate_lock, flags);
    clear_buffer_async_read(bh);
    unlock_buffer(bh);
    tmp = bh;
    do {
        if (!buffer_uptodate(tmp))
            folio_uptodate = 0;
        if (buffer_async_read(tmp)) {
            BUG_ON(!buffer_locked(tmp));
            goto still_busy;
        }
        tmp = tmp->b_this_page;
    } while (tmp != bh);
    spin_unlock_irqrestore(&first->b_uptodate_lock, flags);

    folio_end_read(folio, folio_uptodate);
    return;

still_busy:
    spin_unlock_irqrestore(&first->b_uptodate_lock, flags);
    return;
}

/*
 * I/O completion handler for block_read_full_folio() - pages
 * which come unlocked at the end of I/O.
 */
static void end_buffer_async_read_io(struct buffer_head *bh, int uptodate)
{
    struct inode *inode = bh->b_folio->mapping->host;
    bool decrypt = fscrypt_inode_uses_fs_layer_crypto(inode);
    bool verify = need_fsverity(bh);

    /* Decrypt (with fscrypt) and/or verify (with fsverity) if needed. */
    if (uptodate && (decrypt || verify)) {
#if 0
        struct postprocess_bh_ctx *ctx =
            kmalloc(sizeof(*ctx), GFP_ATOMIC);

        if (ctx) {
            ctx->bh = bh;
            if (decrypt) {
                INIT_WORK(&ctx->work, decrypt_bh);
                fscrypt_enqueue_decrypt_work(&ctx->work);
            } else {
                INIT_WORK(&ctx->work, verify_bh);
                fsverity_enqueue_verify_work(&ctx->work);
            }
            return;
        }
        uptodate = 0;
#endif
        PANIC("Not in this branch.");
    }
    end_buffer_async_read(bh, uptodate);
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
 * Look up the bh in this cpu's LRU.  If it's there, move it to the head.
 */
static struct buffer_head *
lookup_bh_lru(struct block_device *bdev, sector_t block, unsigned size)
{
    struct buffer_head *ret = NULL;
    unsigned int i;

    check_irqs_on();
    bh_lru_lock();
    if (cpu_is_isolated(smp_processor_id())) {
        bh_lru_unlock();
        return NULL;
    }
    for (i = 0; i < BH_LRU_SIZE; i++) {
        struct buffer_head *bh = __this_cpu_read(bh_lrus.bhs[i]);

        if (bh && bh->b_blocknr == block && bh->b_bdev == bdev &&
            bh->b_size == size) {
            if (i) {
                while (i) {
                    __this_cpu_write(bh_lrus.bhs[i],
                        __this_cpu_read(bh_lrus.bhs[i - 1]));
                    i--;
                }
                __this_cpu_write(bh_lrus.bhs[0], bh);
            }
            get_bh(bh);
            ret = bh;
            break;
        }
    }
    bh_lru_unlock();
    return ret;
}

static struct buffer_head *
__find_get_block_slow(struct block_device *bdev, sector_t block, bool atomic)
{
    struct address_space *bd_mapping = bdev->bd_mapping;
    const int blkbits = bd_mapping->host->i_blkbits;
    struct buffer_head *ret = NULL;
    pgoff_t index;
    struct buffer_head *bh;
    struct buffer_head *head;
    struct folio *folio;
    int all_mapped = 1;
    static DEFINE_RATELIMIT_STATE(last_warned, HZ, 1);

    index = ((loff_t)block << blkbits) / PAGE_SIZE;
    folio = __filemap_get_folio(bd_mapping, index, FGP_ACCESSED, 0);
    if (IS_ERR(folio))
        goto out;

    /*
     * Folio lock protects the buffers. Callers that cannot block
     * will fallback to serializing vs try_to_free_buffers() via
     * the i_private_lock.
     */
    if (atomic)
        spin_lock(&bd_mapping->i_private_lock);
    else
        folio_lock(folio);

    head = folio_buffers(folio);
    if (!head)
        goto out_unlock;
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



    PANIC("");
out_unlock:
    if (atomic)
        spin_unlock(&bd_mapping->i_private_lock);
    else
        folio_unlock(folio);
    folio_put(folio);
out:
    return ret;
}

/*
 * Install a buffer_head into this cpu's LRU.  If not already in the LRU, it is
 * inserted at the front, and the buffer_head at the back if any is evicted.
 * Or, if already in the LRU it is moved to the front.
 */
static void bh_lru_install(struct buffer_head *bh)
{
    struct buffer_head *evictee = bh;
    struct bh_lru *b;
    int i;

    check_irqs_on();
    bh_lru_lock();

    /*
     * the refcount of buffer_head in bh_lru prevents dropping the
     * attached page(i.e., try_to_free_buffers) so it could cause
     * failing page migration.
     * Skip putting upcoming bh into bh_lru until migration is done.
     */
    if (lru_cache_disabled() || cpu_is_isolated(smp_processor_id())) {
        bh_lru_unlock();
        return;
    }

    b = this_cpu_ptr(&bh_lrus);
    for (i = 0; i < BH_LRU_SIZE; i++) {
        swap(evictee, b->bhs[i]);
        if (evictee == bh) {
            bh_lru_unlock();
            return;
        }
    }

    get_bh(bh);
    bh_lru_unlock();
    brelse(evictee);
}

inline void touch_buffer(struct buffer_head *bh)
{
    trace_block_touch_buffer(bh);
    folio_mark_accessed(bh->b_folio);
}

/*
 * Perform a pagecache lookup for the matching buffer.  If it's there, refresh
 * it in the LRU and mark it as accessed.  If it is not present then return
 * NULL
 */
static struct buffer_head *
find_get_block_common(struct block_device *bdev, sector_t block,
            unsigned size, bool atomic)
{
    struct buffer_head *bh = lookup_bh_lru(bdev, block, size);

    if (bh == NULL) {
        /* __find_get_block_slow will mark the page accessed */
        bh = __find_get_block_slow(bdev, block, atomic);
        if (bh)
            bh_lru_install(bh);
    } else
        touch_buffer(bh);

    return bh;
}

/* same as __find_get_block() but allows sleeping contexts */
struct buffer_head *
__find_get_block_nonatomic(struct block_device *bdev, sector_t block,
               unsigned size)
{
    return find_get_block_common(bdev, block, size, false);
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

    bio = bio_alloc(bh->b_bdev, 1, opf, GFP_NOIO);

    fscrypt_set_bio_crypt_ctx_bh(bio, bh, GFP_NOIO);

    bio->bi_iter.bi_sector = bh->b_blocknr * (bh->b_size >> 9);
    bio->bi_write_hint = write_hint;

    bio_add_folio_nofail(bio, bh->b_folio, bh->b_size, bh_offset(bh));

    bio->bi_end_io = end_bio_bh_io_sync;
    bio->bi_private = bh;

    /* Take care of bh's that straddle the end of the device */
    guard_bio_eod(bio);

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

static void __invalidate_bh_lrus(struct bh_lru *b)
{
    int i;

    for (i = 0; i < BH_LRU_SIZE; i++) {
        brelse(b->bhs[i]);
        b->bhs[i] = NULL;
    }
}
/*
 * invalidate_bh_lrus() is called rarely - but not only at unmount.
 * This doesn't race because it runs in each cpu either in irq
 * or with preempt disabled.
 */
static void invalidate_bh_lru(void *arg)
{
    struct bh_lru *b = &get_cpu_var(bh_lrus);

    __invalidate_bh_lrus(b);
    put_cpu_var(bh_lrus);
}

void invalidate_bh_lrus(void)
{
    pr_err("%s: No impl\n", __func__);
    //on_each_cpu_cond(has_bh_in_lru, invalidate_bh_lru, NULL, 1);
}

static sector_t blkdev_max_block(struct block_device *bdev, unsigned int size)
{
    sector_t retval = ~((sector_t)0);
    loff_t sz = bdev_nr_bytes(bdev);

    if (sz) {
        unsigned int sizebits = blksize_bits(size);
        retval = (sz >> sizebits);
    }
    return retval;
}

/*
 * Initialise the state of a blockdev folio's buffers.
 */
static sector_t folio_init_buffers(struct folio *folio,
        struct block_device *bdev, unsigned size)
{
    struct buffer_head *head = folio_buffers(folio);
    struct buffer_head *bh = head;
    bool uptodate = folio_test_uptodate(folio);
    sector_t block = div_u64(folio_pos(folio), size);
    sector_t end_block = blkdev_max_block(bdev, size);

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

static inline void link_dev_buffers(struct folio *folio,
        struct buffer_head *head)
{
    struct buffer_head *bh, *tail;

    bh = head;
    do {
        tail = bh;
        bh = bh->b_this_page;
    } while (bh);
    tail->b_this_page = head;
    folio_attach_private(folio, head);
}

/*
 * Create the page-cache folio that contains the requested block.
 *
 * This is used purely for blockdev mappings.
 *
 * Returns false if we have a failure which cannot be cured by retrying
 * without sleeping.  Returns true if we succeeded, or the caller should retry.
 */
static bool grow_dev_folio(struct block_device *bdev, sector_t block,
        pgoff_t index, unsigned size, gfp_t gfp)
{
    struct address_space *mapping = bdev->bd_mapping;
    struct folio *folio;
    struct buffer_head *bh;
    sector_t end_block = 0;

    folio = __filemap_get_folio(mapping, index,
            FGP_LOCK | FGP_ACCESSED | FGP_CREAT, gfp);
    if (IS_ERR(folio))
        return false;

    bh = folio_buffers(folio);
    if (bh) {
        if (bh->b_size == size) {
            end_block = folio_init_buffers(folio, bdev, size);
            goto unlock;
        }

        /*
         * Retrying may succeed; for example the folio may finish
         * writeback, or buffers may be cleaned.  This should not
         * happen very often; maybe we have old buffers attached to
         * this blockdev's page cache and we're trying to change
         * the block size?
         */
        if (!try_to_free_buffers(folio)) {
            end_block = ~0ULL;
            goto unlock;
        }
    }

    bh = folio_alloc_buffers(folio, size, gfp | __GFP_ACCOUNT);
    if (!bh)
        goto unlock;

    /*
     * Link the folio to the buffers and initialise them.  Take the
     * lock to be atomic wrt __find_get_block(), which does not
     * run under the folio lock.
     */
    spin_lock(&mapping->i_private_lock);
    link_dev_buffers(folio, bh);
    end_block = folio_init_buffers(folio, bdev, size);
    spin_unlock(&mapping->i_private_lock);

unlock:
    folio_unlock(folio);
    folio_put(folio);
    return block < end_block;
}

/*
 * Create buffers for the specified block device block's folio.  If
 * that folio was dirty, the buffers are set dirty also.  Returns false
 * if we've hit a permanent error.
 */
static bool grow_buffers(struct block_device *bdev, sector_t block,
        unsigned size, gfp_t gfp)
{
    loff_t pos;

    /*
     * Check for a block which lies outside our maximum possible
     * pagecache index.
     */
    if (check_mul_overflow(block, (sector_t)size, &pos) || pos > MAX_LFS_FILESIZE) {
        printk(KERN_ERR "%s: requested out-of-range block %llu for device %pg\n",
            __func__, (unsigned long long)block,
            bdev);
        return false;
    }

    /* Create a folio with the proper size buffers */
    return grow_dev_folio(bdev, block, pos / PAGE_SIZE, size, gfp);
}

static struct buffer_head *
__getblk_slow(struct block_device *bdev, sector_t block,
         unsigned size, gfp_t gfp)
{
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

        bh = __find_get_block(bdev, block, size);
        if (bh)
            return bh;

        if (!grow_buffers(bdev, block, size, gfp))
            return NULL;
    }

    PANIC("");
}

struct buffer_head *
__find_get_block(struct block_device *bdev, sector_t block, unsigned size)
{
    return find_get_block_common(bdev, block, size, true);
}

/**
 * bdev_getblk - Get a buffer_head in a block device's buffer cache.
 * @bdev: The block device.
 * @block: The block number.
 * @size: The size of buffer_heads for this @bdev.
 * @gfp: The memory allocation flags to use.
 *
 * The returned buffer head has its reference count incremented, but is
 * not locked.  The caller should call brelse() when it has finished
 * with the buffer.  The buffer may not be uptodate.  If needed, the
 * caller can bring it uptodate either by reading it or overwriting it.
 *
 * Return: The buffer head, or NULL if memory could not be allocated.
 */
struct buffer_head *bdev_getblk(struct block_device *bdev, sector_t block,
        unsigned size, gfp_t gfp)
{
    struct buffer_head *bh;

    if (gfpflags_allow_blocking(gfp))
        bh = __find_get_block_nonatomic(bdev, block, size);
    else
        bh = __find_get_block(bdev, block, size);

    might_alloc(gfp);
    if (bh)
        return bh;

    return __getblk_slow(bdev, block, size, gfp);
}

/*
 * Called when truncating a buffer on a page completely.
 */

/* Bits that are cleared during an invalidate */
#define BUFFER_FLAGS_DISCARD \
    (1 << BH_Mapped | 1 << BH_New | 1 << BH_Req | \
     1 << BH_Delay | 1 << BH_Unwritten)

static void discard_buffer(struct buffer_head * bh)
{
    unsigned long b_state;

    lock_buffer(bh);
    clear_buffer_dirty(bh);
    bh->b_bdev = NULL;
    b_state = READ_ONCE(bh->b_state);
    do {
    } while (!try_cmpxchg(&bh->b_state, &b_state,
                  b_state & ~BUFFER_FLAGS_DISCARD));
    unlock_buffer(bh);
}

/**
 * block_invalidate_folio - Invalidate part or all of a buffer-backed folio.
 * @folio: The folio which is affected.
 * @offset: start of the range to invalidate
 * @length: length of the range to invalidate
 *
 * block_invalidate_folio() is called when all or part of the folio has been
 * invalidated by a truncate operation.
 *
 * block_invalidate_folio() does not have to release all buffers, but it must
 * ensure that no dirty buffer is left outside @offset and that no I/O
 * is underway against any of the blocks which are outside the truncation
 * point.  Because the caller is about to free (and possibly reuse) those
 * blocks on-disk.
 */
void block_invalidate_folio(struct folio *folio, size_t offset, size_t length)
{
    struct buffer_head *head, *bh, *next;
    size_t curr_off = 0;
    size_t stop = length + offset;

    BUG_ON(!folio_test_locked(folio));

    /*
     * Check for overflow
     */
    BUG_ON(stop > folio_size(folio) || stop < length);

    head = folio_buffers(folio);
    if (!head)
        return;

    bh = head;
    do {
        size_t next_off = curr_off + bh->b_size;
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
     * We release buffers only if the entire folio is being invalidated.
     * The get_block cached value has been unconditionally invalidated,
     * so real IO is not possible anymore.
     */
    if (length == folio_size(folio))
        filemap_release_folio(folio, 0);
out:
    return;
}

/*
 * The buffer's backing address_space's i_private_lock must be held
 */
static void __remove_assoc_queue(struct buffer_head *bh)
{
    list_del_init(&bh->b_assoc_buffers);
    WARN_ON(!bh->b_assoc_map);
    bh->b_assoc_map = NULL;
}

static inline int buffer_busy(struct buffer_head *bh)
{
    return atomic_read(&bh->b_count) |
        (bh->b_state & ((1 << BH_Dirty) | (1 << BH_Lock)));
}

static bool
drop_buffers(struct folio *folio, struct buffer_head **buffers_to_free)
{
    struct buffer_head *head = folio_buffers(folio);
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
    folio_detach_private(folio);
    return true;
failed:
    return false;
}

/**
 * try_to_free_buffers - Release buffers attached to this folio.
 * @folio: The folio.
 *
 * If any buffers are in use (dirty, under writeback, elevated refcount),
 * no buffers will be freed.
 *
 * If the folio is dirty but all the buffers are clean then we need to
 * be sure to mark the folio clean as well.  This is because the folio
 * may be against a block device, and a later reattachment of buffers
 * to a dirty folio will set *all* buffers dirty.  Which would corrupt
 * filesystem data on the same device.
 *
 * The same applies to regular filesystem folios: if all the buffers are
 * clean then we set the folio clean and proceed.  To do that, we require
 * total exclusion from block_dirty_folio().  That is obtained with
 * i_private_lock.
 *
 * Exclusion against try_to_free_buffers may be obtained by either
 * locking the folio or by holding its mapping's i_private_lock.
 *
 * Context: Process context.  @folio must be locked.  Will not sleep.
 * Return: true if all buffers attached to this folio were freed.
 */
bool try_to_free_buffers(struct folio *folio)
{
    struct address_space * const mapping = folio->mapping;
    struct buffer_head *buffers_to_free = NULL;
    bool ret = 0;

    BUG_ON(!folio_test_locked(folio));
    if (folio_test_writeback(folio))
        return false;

    if (mapping == NULL) {      /* can this still happen? */
        ret = drop_buffers(folio, &buffers_to_free);
        goto out;
    }

    spin_lock(&mapping->i_private_lock);
    ret = drop_buffers(folio, &buffers_to_free);

    /*
     * If the filesystem writes its buffers by hand (eg ext3)
     * then we can have clean buffers against a dirty folio.  We
     * clean the folio here; otherwise the VM will never notice
     * that the filesystem did any IO at all.
     *
     * Also, during truncate, discard_buffer will have marked all
     * the folio's buffers clean.  We discover that here and clean
     * the folio also.
     *
     * i_private_lock must be held over this entire operation in order
     * to synchronise against block_dirty_folio and prevent the
     * dirty bit from being lost.
     */
    if (ret)
        folio_cancel_dirty(folio);
    spin_unlock(&mapping->i_private_lock);
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

/*
 * Block until a buffer comes unlocked.  This doesn't stop it
 * from becoming locked again - you have to lock it yourself
 * if you want to preserve its state.
 */
void __wait_on_buffer(struct buffer_head * bh)
{
    wait_on_bit_io(&bh->b_state, BH_Lock, TASK_UNINTERRUPTIBLE);
}

/**
 * bh_uptodate_or_lock - Test whether the buffer is uptodate
 * @bh: struct buffer_head
 *
 * Return true if the buffer is up-to-date and false,
 * with the buffer locked, if not.
 */
int bh_uptodate_or_lock(struct buffer_head *bh)
{
    if (!buffer_uptodate(bh)) {
        lock_buffer(bh);
        if (!buffer_uptodate(bh))
            return 0;
        unlock_buffer(bh);
    }
    return 1;
}

/**
 * __bh_read - Submit read for a locked buffer
 * @bh: struct buffer_head
 * @op_flags: appending REQ_OP_* flags besides REQ_OP_READ
 * @wait: wait until reading finish
 *
 * Returns zero on success or don't wait, and -EIO on error.
 */
int __bh_read(struct buffer_head *bh, blk_opf_t op_flags, bool wait)
{
    int ret = 0;

    BUG_ON(!buffer_locked(bh));

    get_bh(bh);
    bh->b_end_io = end_buffer_read_sync;
    submit_bh(REQ_OP_READ | op_flags, bh);
    if (wait) {
        wait_on_buffer(bh);
        if (!buffer_uptodate(bh))
            ret = -EIO;
    }
    return ret;
}

void mark_buffer_write_io_error(struct buffer_head *bh)
{
    set_buffer_write_io_error(bh);
    /* FIXME: do we need to set this in both places? */
    if (bh->b_folio && bh->b_folio->mapping)
        mapping_set_error(bh->b_folio->mapping, -EIO);
    if (bh->b_assoc_map) {
        mapping_set_error(bh->b_assoc_map, -EIO);
        errseq_set(&bh->b_assoc_map->host->i_sb->s_wb_err, -EIO);
    }
}

void end_buffer_write_sync(struct buffer_head *bh, int uptodate)
{
    printk("%s: step1 uptodate(%d) bio_list(%lx)\n", __func__, uptodate, current->bio_list);
    if (uptodate) {
        set_buffer_uptodate(bh);
    } else {
        buffer_io_error(bh, ", lost sync page write");
        mark_buffer_write_io_error(bh);
        clear_buffer_uptodate(bh);
    }
    printk("%s: step2 bio_list(%lx)\n", __func__, current->bio_list);
    unlock_buffer(bh);
    printk("%s: step3 bio_list(%lx)\n", __func__, current->bio_list);
    put_bh(bh);
    printk("%s: stepN bio_list(%lx)\n", __func__, current->bio_list);
}

static void __block_commit_write(struct folio *folio, size_t from, size_t to)
{
    size_t block_start, block_end;
    bool partial = false;
    unsigned blocksize;
    struct buffer_head *bh, *head;

    bh = head = folio_buffers(folio);
    if (!bh)
        return;
    blocksize = bh->b_size;

    block_start = 0;
    do {
        block_end = block_start + blocksize;
        if (block_end <= from || block_start >= to) {
            if (!buffer_uptodate(bh))
                partial = true;
        } else {
            set_buffer_uptodate(bh);
            mark_buffer_dirty(bh);
        }
        if (buffer_new(bh))
            clear_buffer_new(bh);

        block_start = block_end;
        bh = bh->b_this_page;
    } while (bh != head);

    /*
     * If this is a partial write which happened to make all buffers
     * uptodate then we can optimize away a bogus read_folio() for
     * the next read(). Here we 'discover' whether the folio went
     * uptodate as a result of this (potentially partial) write.
     */
    if (!partial)
        folio_mark_uptodate(folio);
}

/**
 * mark_buffer_dirty - mark a buffer_head as needing writeout
 * @bh: the buffer_head to mark dirty
 *
 * mark_buffer_dirty() will set the dirty bit against the buffer, then set
 * its backing page dirty, then tag the page as dirty in the page cache
 * and then attach the address_space's inode to its superblock's dirty
 * inode list.
 *
 * mark_buffer_dirty() is atomic.  It takes bh->b_folio->mapping->i_private_lock,
 * i_pages lock and mapping->host->i_lock.
 */
void mark_buffer_dirty(struct buffer_head *bh)
{
    WARN_ON_ONCE(!buffer_uptodate(bh));

    trace_block_dirty_buffer(bh);

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
        struct folio *folio = bh->b_folio;
        struct address_space *mapping = NULL;

        folio_memcg_lock(folio);
        if (!folio_test_set_dirty(folio)) {
            mapping = folio->mapping;
            if (mapping)
                __folio_mark_dirty(folio, mapping, 0);
        }
        folio_memcg_unlock(folio);
        if (mapping)
            __mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
    }
}

int block_write_end(struct file *file, struct address_space *mapping,
            loff_t pos, unsigned len, unsigned copied,
            struct folio *folio, void *fsdata)
{
    size_t start = pos - folio_pos(folio);

    if (unlikely(copied < len)) {
        /*
         * The buffers that were written will now be uptodate, so
         * we don't have to worry about a read_folio reading them
         * and overwriting a partial write. However if we have
         * encountered a short write and only partially written
         * into a buffer, it will not be marked uptodate, so a
         * read_folio might come in and destroy our partial write.
         *
         * Do the simplest thing, and just treat any short write to a
         * non uptodate folio as a zero-length write, and force the
         * caller to redo the whole thing.
         */
        if (!folio_test_uptodate(folio))
            copied = 0;

        folio_zero_new_buffers(folio, start+copied, start+len);
    }
    flush_dcache_folio(folio);

    /* This could be a short (even 0-length) commit */
    __block_commit_write(folio, start, start + copied);

    return copied;
}

/**
 * __bh_read_batch - Submit read for a batch of unlocked buffers
 * @nr: entry number of the buffer batch
 * @bhs: a batch of struct buffer_head
 * @op_flags: appending REQ_OP_* flags besides REQ_OP_READ
 * @force_lock: force to get a lock on the buffer if set, otherwise drops any
 *              buffer that cannot lock.
 *
 * Returns zero on success or don't wait, and -EIO on error.
 */
void __bh_read_batch(int nr, struct buffer_head *bhs[],
             blk_opf_t op_flags, bool force_lock)
{
    int i;

    for (i = 0; i < nr; i++) {
        struct buffer_head *bh = bhs[i];

        if (buffer_uptodate(bh))
            continue;

        if (force_lock)
            lock_buffer(bh);
        else
            if (!trylock_buffer(bh))
                continue;

        if (buffer_uptodate(bh)) {
            unlock_buffer(bh);
            continue;
        }

        bh->b_end_io = end_buffer_read_sync;
        get_bh(bh);
        submit_bh(REQ_OP_READ | op_flags, bh);
    }
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
