#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/bio-integrity.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/iocontext.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
#include <linux/cgroup.h>
#include <linux/highmem.h>
#include <linux/blk-crypto.h>
#include <linux/xarray.h>

#include <trace/events/block.h>
#include "blk.h"
#include "blk-rq-qos.h"
#include "blk-cgroup.h"

#include "../adaptor.h"

#define ALLOC_CACHE_THRESHOLD   16
#define ALLOC_CACHE_MAX     256

struct bio_alloc_cache {
    struct bio      *free_list;
    struct bio      *free_list_irq;
    unsigned int        nr;
    unsigned int        nr_irq;
};

static struct biovec_slab {
    int nr_vecs;
    char *name;
    struct kmem_cache *slab;
} bvec_slabs[] __read_mostly = {
    { .nr_vecs = 16, .name = "biovec-16" },
    { .nr_vecs = 64, .name = "biovec-64" },
    { .nr_vecs = 128, .name = "biovec-128" },
    { .nr_vecs = BIO_MAX_VECS, .name = "biovec-max" },
};

static struct biovec_slab *biovec_slab(unsigned short nr_vecs)
{
    switch (nr_vecs) {
    /* smaller bios use inline vecs */
    case 5 ... 16:
        return &bvec_slabs[0];
    case 17 ... 64:
        return &bvec_slabs[1];
    case 65 ... 128:
        return &bvec_slabs[2];
    case 129 ... BIO_MAX_VECS:
        return &bvec_slabs[3];
    default:
        BUG();
        return NULL;
    }
}

/*
 * Our slab pool management
 */
struct bio_slab {
    struct kmem_cache *slab;
    unsigned int slab_ref;
    unsigned int slab_size;
    char name[12];
};

/*
 * fs_bio_set is the bio_set containing bio and iovec memory pools used by
 * IO code that does not need private memory pools.
 */
struct bio_set fs_bio_set;

static DEFINE_MUTEX(bio_slab_lock);
static DEFINE_XARRAY(bio_slabs);

/**
 * bio_full - check if the bio is full
 * @bio:    bio to check
 * @len:    length of one segment to be added
 *
 * Return true if @bio is full and one segment with @len bytes can't be
 * added to the bio, otherwise return false
 */
static inline bool bio_full(struct bio *bio, unsigned len)
{
    if (bio->bi_vcnt >= bio->bi_max_vecs)
        return true;
    if (bio->bi_iter.bi_size > UINT_MAX - len)
        return true;
    return false;
}

static struct bio *__bio_chain_endio(struct bio *bio)
{
    struct bio *parent = bio->bi_private;

    if (bio->bi_status && !parent->bi_status)
        parent->bi_status = bio->bi_status;
    bio_put(bio);
    return parent;
}

static void bio_chain_endio(struct bio *bio)
{
    bio_endio(__bio_chain_endio(bio));
}

/**
 * bio_truncate - truncate the bio to small size of @new_size
 * @bio:    the bio to be truncated
 * @new_size:   new size for truncating the bio
 *
 * Description:
 *   Truncate the bio to new size of @new_size. If bio_op(bio) is
 *   REQ_OP_READ, zero the truncated part. This function should only
 *   be used for handling corner cases, such as bio eod.
 */
static void bio_truncate(struct bio *bio, unsigned new_size)
{
    PANIC("");
}

/**
 * guard_bio_eod - truncate a BIO to fit the block device
 * @bio:    bio to truncate
 *
 * This allows us to do IO even on the odd last sectors of a device, even if the
 * block size is some multiple of the physical sector size.
 *
 * We'll just truncate the bio to the size of the device, and clear the end of
 * the buffer head manually.  Truly out-of-range accesses will turn into actual
 * I/O errors, this only handles the "we need to be able to do I/O at the final
 * sector" case.
 */
void guard_bio_eod(struct bio *bio)
{
    sector_t maxsector = bdev_nr_sectors(bio->bi_bdev);

    pr_debug("%s: maxsector(%lu)\n", __func__, maxsector);
    if (!maxsector)
        return;

    /*
     * If the *whole* IO is past the end of the device,
     * let it through, and the IO layer will turn it into
     * an EIO.
     */
    if (unlikely(bio->bi_iter.bi_sector >= maxsector))
        return;

    maxsector -= bio->bi_iter.bi_sector;
    if (likely((bio->bi_iter.bi_size >> 9) <= maxsector))
        return;

    bio_truncate(bio, maxsector << 9);
}

/*
 * Users of this function have their own bio allocation. Subsequently,
 * they must remember to pair any call to bio_init() with bio_uninit()
 * when IO has completed, or when the bio is released.
 */
void bio_init(struct bio *bio, struct block_device *bdev, struct bio_vec *table,
          unsigned short max_vecs, blk_opf_t opf)
{
    bio->bi_next = NULL;
    bio->bi_bdev = bdev;
    bio->bi_opf = opf;
    bio->bi_flags = 0;
    bio->bi_ioprio = 0;
    bio->bi_write_hint = 0;
    bio->bi_status = 0;
    bio->bi_iter.bi_sector = 0;
    bio->bi_iter.bi_size = 0;
    bio->bi_iter.bi_idx = 0;
    bio->bi_iter.bi_bvec_done = 0;
    bio->bi_end_io = NULL;
    bio->bi_private = NULL;
#ifdef CONFIG_BLK_CGROUP
    bio->bi_blkg = NULL;
    bio->bi_issue.value = 0;
#if 0
    if (bdev)
        bio_associate_blkg(bio);
#endif
#ifdef CONFIG_BLK_CGROUP_IOCOST
    bio->bi_iocost_cost = 0;
#endif
#endif
#ifdef CONFIG_BLK_INLINE_ENCRYPTION
    bio->bi_crypt_context = NULL;
#endif
#ifdef CONFIG_BLK_DEV_INTEGRITY
    bio->bi_integrity = NULL;
#endif
    bio->bi_vcnt = 0;

    atomic_set(&bio->__bi_remaining, 1);
    atomic_set(&bio->__bi_cnt, 1);
    bio->bi_cookie = BLK_QC_T_NONE;

    bio->bi_max_vecs = max_vecs;
    bio->bi_io_vec = table;
    bio->bi_pool = NULL;
}

static void bio_alloc_rescue(struct work_struct *work)
{
    PANIC("");
}

static inline unsigned int bs_bio_slab_size(struct bio_set *bs)
{
    return bs->front_pad + sizeof(struct bio) + bs->back_pad;
}

static struct bio_slab *create_bio_slab(unsigned int size)
{
    struct bio_slab *bslab = kzalloc(sizeof(*bslab), GFP_KERNEL);

    if (!bslab)
        return NULL;

    snprintf(bslab->name, sizeof(bslab->name), "bio-%d", size);
    bslab->slab = kmem_cache_create(bslab->name, size,
            ARCH_KMALLOC_MINALIGN,
            SLAB_HWCACHE_ALIGN | SLAB_TYPESAFE_BY_RCU, NULL);
    if (!bslab->slab)
        goto fail_alloc_slab;

    bslab->slab_ref = 1;
    bslab->slab_size = size;

    if (!xa_err(xa_store(&bio_slabs, size, bslab, GFP_KERNEL)))
        return bslab;

    kmem_cache_destroy(bslab->slab);

fail_alloc_slab:
    kfree(bslab);
    return NULL;
}

static struct kmem_cache *bio_find_or_create_slab(struct bio_set *bs)
{
    unsigned int size = bs_bio_slab_size(bs);
    struct bio_slab *bslab;

    mutex_lock(&bio_slab_lock);
    bslab = xa_load(&bio_slabs, size);
    if (bslab)
        bslab->slab_ref++;
    else
        bslab = create_bio_slab(size);
    mutex_unlock(&bio_slab_lock);

    if (bslab)
        return bslab->slab;
    return NULL;
}

/**
 * bioset_init - Initialize a bio_set
 * @bs:     pool to initialize
 * @pool_size:  Number of bio and bio_vecs to cache in the mempool
 * @front_pad:  Number of bytes to allocate in front of the returned bio
 * @flags:  Flags to modify behavior, currently %BIOSET_NEED_BVECS
 *              and %BIOSET_NEED_RESCUER
 *
 * Description:
 *    Set up a bio_set to be used with @bio_alloc_bioset. Allows the caller
 *    to ask for a number of bytes to be allocated in front of the bio.
 *    Front pad allocation is useful for embedding the bio inside
 *    another structure, to avoid allocating extra data to go with the bio.
 *    Note that the bio must be embedded at the END of that structure always,
 *    or things will break badly.
 *    If %BIOSET_NEED_BVECS is set in @flags, a separate pool will be allocated
 *    for allocating iovecs.  This pool is not needed e.g. for bio_init_clone().
 *    If %BIOSET_NEED_RESCUER is set, a workqueue is created which can be used
 *    to dispatch queued requests when the mempool runs out of space.
 *
 */
int bioset_init(struct bio_set *bs,
        unsigned int pool_size,
        unsigned int front_pad,
        int flags)
{
    bs->front_pad = front_pad;
    if (flags & BIOSET_NEED_BVECS)
        bs->back_pad = BIO_INLINE_VECS * sizeof(struct bio_vec);
    else
        bs->back_pad = 0;

    spin_lock_init(&bs->rescue_lock);
    bio_list_init(&bs->rescue_list);
    INIT_WORK(&bs->rescue_work, bio_alloc_rescue);

    bs->bio_slab = bio_find_or_create_slab(bs);
    if (!bs->bio_slab)
        return -ENOMEM;

    pr_debug("%s: bs(%lx) pool(%lx)\n", __func__, bs, &bs->bio_pool);
    if (mempool_init_slab_pool(&bs->bio_pool, pool_size, bs->bio_slab))
        goto bad;

    if ((flags & BIOSET_NEED_BVECS) &&
        biovec_init_pool(&bs->bvec_pool, pool_size))
        goto bad;

    if (flags & BIOSET_NEED_RESCUER) {
        bs->rescue_workqueue = alloc_workqueue("bioset",
                            WQ_MEM_RECLAIM, 0);
        if (!bs->rescue_workqueue)
            goto bad;
    }
    if (flags & BIOSET_PERCPU_CACHE) {
        bs->cache = alloc_percpu(struct bio_alloc_cache);
        if (!bs->cache)
            goto bad;
        cpuhp_state_add_instance_nocalls(CPUHP_BIO_DEAD, &bs->cpuhp_dead);
    }

    return 0;
bad:
    PANIC("ERR");
    bioset_exit(bs);
    return -ENOMEM;
}

static void bio_alloc_irq_cache_splice(struct bio_alloc_cache *cache)
{
    unsigned long flags;

    /* cache->free_list must be empty */
    if (WARN_ON_ONCE(cache->free_list))
        return;

    local_irq_save(flags);
    cache->free_list = cache->free_list_irq;
    cache->free_list_irq = NULL;
    cache->nr += cache->nr_irq;
    cache->nr_irq = 0;
    local_irq_restore(flags);
}

static struct bio *bio_alloc_percpu_cache(struct block_device *bdev,
        unsigned short nr_vecs, blk_opf_t opf, gfp_t gfp,
        struct bio_set *bs)
{
    struct bio_alloc_cache *cache;
    struct bio *bio;

    cache = per_cpu_ptr(bs->cache, get_cpu());
    if (!cache->free_list) {
        if (READ_ONCE(cache->nr_irq) >= ALLOC_CACHE_THRESHOLD)
            bio_alloc_irq_cache_splice(cache);
        if (!cache->free_list) {
            put_cpu();
            return NULL;
        }
    }
    bio = cache->free_list;
    cache->free_list = bio->bi_next;
    cache->nr--;
    put_cpu();

    bio_init(bio, bdev, nr_vecs ? bio->bi_inline_vecs : NULL, nr_vecs, opf);
    bio->bi_pool = bs;
    return bio;
}

static void punt_bios_to_rescuer(struct bio_set *bs)
{
    PANIC("");
}

/**
 * bio_alloc_bioset - allocate a bio for I/O
 * @bdev:   block device to allocate the bio for (can be %NULL)
 * @nr_vecs:    number of bvecs to pre-allocate
 * @opf:    operation and flags for bio
 * @gfp_mask:   the GFP_* mask given to the slab allocator
 * @bs:     the bio_set to allocate from.
 *
 * Allocate a bio from the mempools in @bs.
 *
 * If %__GFP_DIRECT_RECLAIM is set then bio_alloc will always be able to
 * allocate a bio.  This is due to the mempool guarantees.  To make this work,
 * callers must never allocate more than 1 bio at a time from the general pool.
 * Callers that need to allocate more than 1 bio must always submit the
 * previously allocated bio for IO before attempting to allocate a new one.
 * Failure to do so can cause deadlocks under memory pressure.
 *
 * Note that when running under submit_bio_noacct() (i.e. any block driver),
 * bios are not submitted until after you return - see the code in
 * submit_bio_noacct() that converts recursion into iteration, to prevent
 * stack overflows.
 *
 * This would normally mean allocating multiple bios under submit_bio_noacct()
 * would be susceptible to deadlocks, but we have
 * deadlock avoidance code that resubmits any blocked bios from a rescuer
 * thread.
 *
 * However, we do not guarantee forward progress for allocations from other
 * mempools. Doing multiple allocations from the same mempool under
 * submit_bio_noacct() should be avoided - instead, use bio_set's front_pad
 * for per bio allocations.
 *
 * Returns: Pointer to new bio on success, NULL on failure.
 */
struct bio *bio_alloc_bioset(struct block_device *bdev, unsigned short nr_vecs,
                 blk_opf_t opf, gfp_t gfp_mask,
                 struct bio_set *bs)
{
    gfp_t saved_gfp = gfp_mask;
    struct bio *bio;
    void *p;

    /* should not use nobvec bioset for nr_vecs > 0 */
    if (WARN_ON_ONCE(!mempool_initialized(&bs->bvec_pool) && nr_vecs > 0))
        return NULL;

    if (opf & REQ_ALLOC_CACHE) {
        if (bs->cache && nr_vecs <= BIO_INLINE_VECS) {
            bio = bio_alloc_percpu_cache(bdev, nr_vecs, opf,
                             gfp_mask, bs);
            if (bio)
                return bio;
            /*
             * No cached bio available, bio returned below marked with
             * REQ_ALLOC_CACHE to particpate in per-cpu alloc cache.
             */
        } else {
            opf &= ~REQ_ALLOC_CACHE;
        }
    }

    /*
     * submit_bio_noacct() converts recursion to iteration; this means if
     * we're running beneath it, any bios we allocate and submit will not be
     * submitted (and thus freed) until after we return.
     *
     * This exposes us to a potential deadlock if we allocate multiple bios
     * from the same bio_set() while running underneath submit_bio_noacct().
     * If we were to allocate multiple bios (say a stacking block driver
     * that was splitting bios), we would deadlock if we exhausted the
     * mempool's reserve.
     *
     * We solve this, and guarantee forward progress, with a rescuer
     * workqueue per bio_set. If we go to allocate and there are bios on
     * current->bio_list, we first try the allocation without
     * __GFP_DIRECT_RECLAIM; if that fails, we punt those bios we would be
     * blocking to the rescuer workqueue before we retry with the original
     * gfp_flags.
     */
    if (current->bio_list &&
        (!bio_list_empty(&current->bio_list[0]) ||
         !bio_list_empty(&current->bio_list[1])) &&
        bs->rescue_workqueue)
        gfp_mask &= ~__GFP_DIRECT_RECLAIM;

    pr_debug("%s: bs(%lx) pool(%lx)\n", __func__, bs, &bs->bio_pool);
    p = mempool_alloc(&bs->bio_pool, gfp_mask);
    if (!p && gfp_mask != saved_gfp) {
        punt_bios_to_rescuer(bs);
        gfp_mask = saved_gfp;
        p = mempool_alloc(&bs->bio_pool, gfp_mask);
    }
    if (unlikely(!p))
        return NULL;
    if (!mempool_is_saturated(&bs->bio_pool))
        opf &= ~REQ_ALLOC_CACHE;

    bio = p + bs->front_pad;
    if (nr_vecs > BIO_INLINE_VECS) {
        struct bio_vec *bvl = NULL;

        bvl = bvec_alloc(&bs->bvec_pool, &nr_vecs, gfp_mask);
        if (!bvl && gfp_mask != saved_gfp) {
            punt_bios_to_rescuer(bs);
            gfp_mask = saved_gfp;
            bvl = bvec_alloc(&bs->bvec_pool, &nr_vecs, gfp_mask);
        }
        if (unlikely(!bvl))
            goto err_free;

        bio_init(bio, bdev, bvl, nr_vecs, opf);
    } else if (nr_vecs) {
        bio_init(bio, bdev, bio->bi_inline_vecs, BIO_INLINE_VECS, opf);
    } else {
        bio_init(bio, bdev, NULL, 0, opf);
    }

    bio->bi_pool = bs;
    return bio;

err_free:
    mempool_free(p, &bs->bio_pool);
    return NULL;
}

/*
 * Make the first allocation restricted and don't dump info on allocation
 * failures, since we'll fall back to the mempool in case of failure.
 */
static inline gfp_t bvec_alloc_gfp(gfp_t gfp)
{
    return (gfp & ~(__GFP_DIRECT_RECLAIM | __GFP_IO)) |
        __GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN;
}

struct bio_vec *bvec_alloc(mempool_t *pool, unsigned short *nr_vecs,
        gfp_t gfp_mask)
{
    struct biovec_slab *bvs = biovec_slab(*nr_vecs);

    if (WARN_ON_ONCE(!bvs))
        return NULL;

    /*
     * Upgrade the nr_vecs request to take full advantage of the allocation.
     * We also rely on this in the bvec_free path.
     */
    *nr_vecs = bvs->nr_vecs;

    /*
     * Try a slab allocation first for all smaller allocations.  If that
     * fails and __GFP_DIRECT_RECLAIM is set retry with the mempool.
     * The mempool is sized to handle up to BIO_MAX_VECS entries.
     */
    if (*nr_vecs < BIO_MAX_VECS) {
        struct bio_vec *bvl;

        bvl = kmem_cache_alloc(bvs->slab, bvec_alloc_gfp(gfp_mask));
        if (likely(bvl) || !(gfp_mask & __GFP_DIRECT_RECLAIM))
            return bvl;
        *nr_vecs = BIO_MAX_VECS;
    }

    return mempool_alloc(pool, gfp_mask);
}

static int bio_cpu_dead(unsigned int cpu, struct hlist_node *node)
{
    PANIC("");
}

/*
 * create memory pools for biovec's in a bio_set.
 * use the global biovec slabs created for general use.
 */
int biovec_init_pool(mempool_t *pool, int pool_entries)
{
    struct biovec_slab *bp = bvec_slabs + ARRAY_SIZE(bvec_slabs) - 1;

    return mempool_init_slab_pool(pool, pool_entries, bp->slab);
}

/**
 * __bio_add_page - add page(s) to a bio in a new segment
 * @bio: destination bio
 * @page: start page to add
 * @len: length of the data to add, may cross pages
 * @off: offset of the data relative to @page, may cross pages
 *
 * Add the data at @page + @off to @bio as a new bvec.  The caller must ensure
 * that @bio has space for another bvec.
 */
void __bio_add_page(struct bio *bio, struct page *page,
        unsigned int len, unsigned int off)
{
    WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED));
    WARN_ON_ONCE(bio_full(bio, len));

    bvec_set_page(&bio->bi_io_vec[bio->bi_vcnt], page, len, off);
    bio->bi_iter.bi_size += len;
    bio->bi_vcnt++;
}

void bio_add_folio_nofail(struct bio *bio, struct folio *folio, size_t len,
              size_t off)
{
    unsigned long nr = off / PAGE_SIZE;

    WARN_ON_ONCE(len > UINT_MAX);
    __bio_add_page(bio, folio_page(folio, nr), len, off % PAGE_SIZE);
}

static inline bool bio_remaining_done(struct bio *bio)
{
    /*
     * If we're not chaining, then ->__bi_remaining is always 1 and
     * we always end io on the first invocation.
     */
    if (!bio_flagged(bio, BIO_CHAIN))
        return true;

    BUG_ON(atomic_read(&bio->__bi_remaining) <= 0);

    if (atomic_dec_and_test(&bio->__bi_remaining)) {
        bio_clear_flag(bio, BIO_CHAIN);
        return true;
    }

    return false;
}

/**
 * bio_endio - end I/O on a bio
 * @bio:    bio
 *
 * Description:
 *   bio_endio() will end I/O on the whole bio. bio_endio() is the preferred
 *   way to end I/O on a bio. No one should call bi_end_io() directly on a
 *   bio unless they own it and thus know that it has an end_io function.
 *
 *   bio_endio() can be called several times on a bio that has been chained
 *   using bio_chain().  The ->bi_end_io() function will only be called the
 *   last time.
 **/
void bio_endio(struct bio *bio)
{
again:
    if (!bio_remaining_done(bio))
        return;
    if (!bio_integrity_endio(bio))
        return;

    blk_zone_bio_endio(bio);

    rq_qos_done_bio(bio);

    if (bio->bi_bdev && bio_flagged(bio, BIO_TRACE_COMPLETION)) {
        trace_block_bio_complete(bdev_get_queue(bio->bi_bdev), bio);
        bio_clear_flag(bio, BIO_TRACE_COMPLETION);
    }

    /*
     * Need to have a real endio function for chained bios, otherwise
     * various corner cases will break (like stacking block devices that
     * save/restore bi_end_io) - however, we want to avoid unbounded
     * recursion and blowing the stack. Tail call optimization would
     * handle this, but compiling with frame pointers also disables
     * gcc's sibling call optimization.
     */
    if (bio->bi_end_io == bio_chain_endio) {
        bio = __bio_chain_endio(bio);
        goto again;
    }

#ifdef CONFIG_BLK_CGROUP
    /*
     * Release cgroup info.  We shouldn't have to do this here, but quite
     * a few callers of bio_init fail to call bio_uninit, so we cover up
     * for that here at least for now.
     */
    if (bio->bi_blkg) {
        blkg_put(bio->bi_blkg);
        bio->bi_blkg = NULL;
    }
#endif

    if (bio->bi_end_io)
        bio->bi_end_io(bio);
}

void __bio_advance(struct bio *bio, unsigned bytes)
{
    if (bio_integrity(bio))
        bio_integrity_advance(bio, bytes);

    bio_crypt_advance(bio, bytes);
    bio_advance_iter(bio, &bio->bi_iter, bytes);
}

void bio_uninit(struct bio *bio)
{
#ifdef CONFIG_BLK_CGROUP
    if (bio->bi_blkg) {
        blkg_put(bio->bi_blkg);
        bio->bi_blkg = NULL;
    }
#endif
    if (bio_integrity(bio))
        bio_integrity_free(bio);

    bio_crypt_free_ctx(bio);
}

static void bio_free(struct bio *bio)
{
    struct bio_set *bs = bio->bi_pool;
    void *p = bio;

    WARN_ON_ONCE(!bs);

    bio_uninit(bio);
    bvec_free(&bs->bvec_pool, bio->bi_io_vec, bio->bi_max_vecs);
    mempool_free(p - bs->front_pad, &bs->bio_pool);
}

void bvec_free(mempool_t *pool, struct bio_vec *bv, unsigned short nr_vecs)
{
    BUG_ON(nr_vecs > BIO_MAX_VECS);

    if (nr_vecs == BIO_MAX_VECS)
        mempool_free(bv, pool);
    else if (nr_vecs > BIO_INLINE_VECS)
        kmem_cache_free(biovec_slab(nr_vecs)->slab, bv);
}

static inline void bio_put_percpu_cache(struct bio *bio)
{
    struct bio_alloc_cache *cache;

#if 0
    cache = per_cpu_ptr(bio->bi_pool->cache, get_cpu());
    if (READ_ONCE(cache->nr_irq) + cache->nr > ALLOC_CACHE_MAX)
        goto out_free;

    if (in_task()) {
        bio_uninit(bio);
        bio->bi_next = cache->free_list;
        /* Not necessary but helps not to iopoll already freed bios */
        bio->bi_bdev = NULL;
        cache->free_list = bio;
        cache->nr++;
    } else if (in_hardirq()) {
        lockdep_assert_irqs_disabled();

        bio_uninit(bio);
        bio->bi_next = cache->free_list_irq;
        cache->free_list_irq = bio;
        cache->nr_irq++;
    } else {
        goto out_free;
    }
    put_cpu();
    return;
out_free:
    put_cpu();
    bio_free(bio);
#endif
    PANIC("");
}

/**
 * bio_put - release a reference to a bio
 * @bio:   bio to release reference to
 *
 * Description:
 *   Put a reference to a &struct bio, either one you have gotten with
 *   bio_alloc, bio_get or bio_clone_*. The last put of a bio will free it.
 **/
void bio_put(struct bio *bio)
{
    if (unlikely(bio_flagged(bio, BIO_REFFED))) {
        BUG_ON(!atomic_read(&bio->__bi_cnt));
        if (!atomic_dec_and_test(&bio->__bi_cnt))
            return;
    }
    if (bio->bi_opf & REQ_ALLOC_CACHE)
        bio_put_percpu_cache(bio);
    else
        bio_free(bio);
}

static bool bvec_try_merge_page(struct bio_vec *bv, struct page *page,
        unsigned int len, unsigned int off, bool *same_page)
{
    size_t bv_end = bv->bv_offset + bv->bv_len;
    phys_addr_t vec_end_addr = page_to_phys(bv->bv_page) + bv_end - 1;
    phys_addr_t page_addr = page_to_phys(page);

    if (vec_end_addr + 1 != page_addr + off)
        return false;
    if (xen_domain() && !xen_biovec_phys_mergeable(bv, page))
        return false;
    if (!zone_device_pages_have_same_pgmap(bv->bv_page, page))
        return false;

    *same_page = ((vec_end_addr & PAGE_MASK) == ((page_addr + off) &
             PAGE_MASK));
    if (!*same_page) {
        if (IS_ENABLED(CONFIG_KMSAN))
            return false;
        if (bv->bv_page + bv_end / PAGE_SIZE != page + off / PAGE_SIZE)
            return false;
    }

    bv->bv_len += len;
    return true;
}

/**
 * bio_add_folio - Attempt to add part of a folio to a bio.
 * @bio: BIO to add to.
 * @folio: Folio to add.
 * @len: How many bytes from the folio to add.
 * @off: First byte in this folio to add.
 *
 * Filesystems that use folios can call this function instead of calling
 * bio_add_page() for each page in the folio.  If @off is bigger than
 * PAGE_SIZE, this function can create a bio_vec that starts in a page
 * after the bv_page.  BIOs do not support folios that are 4GiB or larger.
 *
 * Return: Whether the addition was successful.
 */
bool bio_add_folio(struct bio *bio, struct folio *folio, size_t len,
           size_t off)
{
    unsigned long nr = off / PAGE_SIZE;

    if (len > UINT_MAX)
        return false;
    return bio_add_page(bio, folio_page(folio, nr), len, off % PAGE_SIZE) > 0;
}

/**
 *  bio_add_page    -   attempt to add page(s) to bio
 *  @bio: destination bio
 *  @page: start page to add
 *  @len: vec entry length, may cross pages
 *  @offset: vec entry offset relative to @page, may cross pages
 *
 *  Attempt to add page(s) to the bio_vec maplist. This will only fail
 *  if either bio->bi_vcnt == bio->bi_max_vecs or it's a cloned bio.
 */
int bio_add_page(struct bio *bio, struct page *page,
         unsigned int len, unsigned int offset)
{
    bool same_page = false;

    if (WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED)))
        return 0;
    if (bio->bi_iter.bi_size > UINT_MAX - len)
        return 0;

    if (bio->bi_vcnt > 0 &&
        bvec_try_merge_page(&bio->bi_io_vec[bio->bi_vcnt - 1],
                page, len, offset, &same_page)) {
        bio->bi_iter.bi_size += len;
        return len;
    }

    if (bio->bi_vcnt >= bio->bi_max_vecs)
        return 0;
    __bio_add_page(bio, page, len, offset);
    return len;
}

static void submit_bio_wait_endio(struct bio *bio)
{
    complete(bio->bi_private);
}

/**
 * submit_bio_wait - submit a bio, and wait until it completes
 * @bio: The &struct bio which describes the I/O
 *
 * Simple wrapper around submit_bio(). Returns 0 on success, or the error from
 * bio_endio() on failure.
 *
 * WARNING: Unlike to how submit_bio() is usually used, this function does not
 * result in bio reference to be consumed. The caller must drop the reference
 * on his own.
 */
int submit_bio_wait(struct bio *bio)
{
    DECLARE_COMPLETION_ONSTACK_MAP(done,
            bio->bi_bdev->bd_disk->lockdep_map);

    bio->bi_private = &done;
    bio->bi_end_io = submit_bio_wait_endio;
    bio->bi_opf |= REQ_SYNC;
    submit_bio(bio);
    blk_wait_io(&done);

    return blk_status_to_errno(bio->bi_status);
}

static int __init init_bio(void)
{
    int i;

    BUILD_BUG_ON(BIO_FLAG_LAST > 8 * sizeof_field(struct bio, bi_flags));

    bio_integrity_init();

    for (i = 0; i < ARRAY_SIZE(bvec_slabs); i++) {
        struct biovec_slab *bvs = bvec_slabs + i;

        bvs->slab = kmem_cache_create(bvs->name,
                bvs->nr_vecs * sizeof(struct bio_vec), 0,
                SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
    }

#if 0
    cpuhp_setup_state_multi(CPUHP_BIO_DEAD, "block/bio:dead", NULL,
                    bio_cpu_dead);
#endif

    if (bioset_init(&fs_bio_set, BIO_POOL_SIZE, 0,
            BIOSET_NEED_BVECS | BIOSET_PERCPU_CACHE))
        panic("bio: can't allocate bios\n");

    if (bioset_integrity_create(&fs_bio_set, BIO_POOL_SIZE))
        panic("bio: can't create integrity pool\n");

    return 0;
}
subsys_initcall(init_bio);

void cl_init_bio(void)
{
    init_bio();
}
