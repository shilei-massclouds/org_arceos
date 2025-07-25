#include <linux/blk-mq.h>
#include <linux/crash_dump.h>
#include <linux/kmemleak.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-pm.h"
#include "blk-stat.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"

#include "../adaptor.h"

static int blk_mq_init_request(struct blk_mq_tag_set *set, struct request *rq,
                   unsigned int hctx_idx, int node)
{
    int ret;

    if (set->ops->init_request) {
        ret = set->ops->init_request(set, rq, hctx_idx, node);
        if (ret)
            return ret;
    }

    WRITE_ONCE(rq->state, MQ_RQ_IDLE);
    return 0;
}

static void blk_mq_update_queue_map(struct blk_mq_tag_set *set)
{
    /*
     * blk_mq_map_queues() and multiple .map_queues() implementations
     * expect that set->map[HCTX_TYPE_DEFAULT].nr_queues is set to the
     * number of hardware queues.
     */
    if (set->nr_maps == 1)
        set->map[HCTX_TYPE_DEFAULT].nr_queues = set->nr_hw_queues;

    if (set->ops->map_queues) {
        int i;

        /*
         * transport .map_queues is usually done in the following
         * way:
         *
         * for (queue = 0; queue < set->nr_hw_queues; queue++) {
         *  mask = get_cpu_mask(queue)
         *  for_each_cpu(cpu, mask)
         *      set->map[x].mq_map[cpu] = queue;
         * }
         *
         * When we need to remap, the table has to be cleared for
         * killing stale mapping since one CPU may not be mapped
         * to any hw queue.
         */
        for (i = 0; i < set->nr_maps; i++)
            blk_mq_clear_mq_map(&set->map[i]);

        set->ops->map_queues(set);
    } else {
        BUG_ON(set->nr_maps > 1);
        blk_mq_map_queues(&set->map[HCTX_TYPE_DEFAULT]);
    }
}

static enum hctx_type hctx_idx_to_type(struct blk_mq_tag_set *set,
        unsigned int hctx_idx)
{
    int i;

    for (i = 0; i < set->nr_maps; i++) {
        unsigned int start = set->map[i].queue_offset;
        unsigned int end = start + set->map[i].nr_queues;

        if (hctx_idx >= start && hctx_idx < end)
            break;
    }

    if (i >= set->nr_maps)
        i = HCTX_TYPE_DEFAULT;

    return i;
}

static int blk_mq_get_hctx_node(struct blk_mq_tag_set *set,
        unsigned int hctx_idx)
{
    enum hctx_type type = hctx_idx_to_type(set, hctx_idx);

    return blk_mq_hw_queue_to_node(&set->map[type], hctx_idx);
}

static struct blk_mq_tags *blk_mq_alloc_rq_map(struct blk_mq_tag_set *set,
                           unsigned int hctx_idx,
                           unsigned int nr_tags,
                           unsigned int reserved_tags)
{
    int node = blk_mq_get_hctx_node(set, hctx_idx);
    struct blk_mq_tags *tags;

    if (node == NUMA_NO_NODE)
        node = set->numa_node;

    tags = blk_mq_init_tags(nr_tags, reserved_tags, node,
                BLK_MQ_FLAG_TO_ALLOC_POLICY(set->flags));
    if (!tags)
        return NULL;

    tags->rqs = kcalloc_node(nr_tags, sizeof(struct request *),
                 GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
                 node);
    if (!tags->rqs)
        goto err_free_tags;

    tags->static_rqs = kcalloc_node(nr_tags, sizeof(struct request *),
                    GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
                    node);
    if (!tags->static_rqs)
        goto err_free_rqs;

    return tags;

err_free_rqs:
    kfree(tags->rqs);
err_free_tags:
    blk_mq_free_tags(tags);
    return NULL;
}

static size_t order_to_size(unsigned int order)
{
    return (size_t)PAGE_SIZE << order;
}

static int blk_mq_alloc_rqs(struct blk_mq_tag_set *set,
                struct blk_mq_tags *tags,
                unsigned int hctx_idx, unsigned int depth)
{
    unsigned int i, j, entries_per_page, max_order = 4;
    int node = blk_mq_get_hctx_node(set, hctx_idx);
    size_t rq_size, left;

    if (node == NUMA_NO_NODE)
        node = set->numa_node;

    INIT_LIST_HEAD(&tags->page_list);

    /*
     * rq_size is the size of the request plus driver payload, rounded
     * to the cacheline size
     */
    rq_size = round_up(sizeof(struct request) + set->cmd_size,
                cache_line_size());
    left = rq_size * depth;

    for (i = 0; i < depth; ) {
        int this_order = max_order;
        struct page *page;
        int to_do;
        void *p;

        while (this_order && left < order_to_size(this_order - 1))
            this_order--;

        do {
            page = alloc_pages_node(node,
                GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY | __GFP_ZERO,
                this_order);
            if (page)
                break;
            if (!this_order--)
                break;
            if (order_to_size(this_order) < rq_size)
                break;
        } while (1);

        if (!page)
            goto fail;

        page->private = this_order;
        list_add_tail(&page->lru, &tags->page_list);

        p = page_address(page);
        /*
         * Allow kmemleak to scan these pages as they contain pointers
         * to additional allocations like via ops->init_request().
         */
        kmemleak_alloc(p, order_to_size(this_order), 1, GFP_NOIO);
        entries_per_page = order_to_size(this_order) / rq_size;
        to_do = min(entries_per_page, depth - i);
        left -= to_do * rq_size;
        for (j = 0; j < to_do; j++) {
            struct request *rq = p;

            tags->static_rqs[i] = rq;
            if (blk_mq_init_request(set, rq, hctx_idx, node)) {
                tags->static_rqs[i] = NULL;
                goto fail;
            }

            p += rq_size;
            i++;
        }
    }
    return 0;

fail:
    blk_mq_free_rqs(set, tags, hctx_idx);
    return -ENOMEM;
}

struct blk_mq_tags *blk_mq_alloc_map_and_rqs(struct blk_mq_tag_set *set,
                         unsigned int hctx_idx,
                         unsigned int depth)
{
    struct blk_mq_tags *tags;
    int ret;

    tags = blk_mq_alloc_rq_map(set, hctx_idx, depth, set->reserved_tags);
    if (!tags)
        return NULL;

    ret = blk_mq_alloc_rqs(set, tags, hctx_idx, depth);
    if (ret) {
        blk_mq_free_rq_map(tags);
        return NULL;
    }

    return tags;
}

static void __blk_mq_free_map_and_rqs(struct blk_mq_tag_set *set,
                      unsigned int hctx_idx)
{
    if (!blk_mq_is_shared_tags(set->flags))
        blk_mq_free_map_and_rqs(set, set->tags[hctx_idx], hctx_idx);

    set->tags[hctx_idx] = NULL;
}

static bool __blk_mq_alloc_map_and_rqs(struct blk_mq_tag_set *set,
                       int hctx_idx)
{
    if (blk_mq_is_shared_tags(set->flags)) {
        set->tags[hctx_idx] = set->shared_tags;

        return true;
    }

    set->tags[hctx_idx] = blk_mq_alloc_map_and_rqs(set, hctx_idx,
                               set->queue_depth);

    return set->tags[hctx_idx];
}

static int __blk_mq_alloc_rq_maps(struct blk_mq_tag_set *set)
{
    int i;

    if (blk_mq_is_shared_tags(set->flags)) {
        set->shared_tags = blk_mq_alloc_map_and_rqs(set,
                        BLK_MQ_NO_HCTX_IDX,
                        set->queue_depth);
        if (!set->shared_tags)
            return -ENOMEM;
    }

    for (i = 0; i < set->nr_hw_queues; i++) {
        if (!__blk_mq_alloc_map_and_rqs(set, i))
            goto out_unwind;
        cond_resched();
    }

    return 0;

out_unwind:
    while (--i >= 0)
        __blk_mq_free_map_and_rqs(set, i);

    if (blk_mq_is_shared_tags(set->flags)) {
        blk_mq_free_map_and_rqs(set, set->shared_tags,
                    BLK_MQ_NO_HCTX_IDX);
    }

    return -ENOMEM;
}

/*
 * Allocate the request maps associated with this tag_set. Note that this
 * may reduce the depth asked for, if memory is tight. set->queue_depth
 * will be updated to reflect the allocated depth.
 */
static int blk_mq_alloc_set_map_and_rqs(struct blk_mq_tag_set *set)
{
    unsigned int depth;
    int err;

    depth = set->queue_depth;
    do {
        err = __blk_mq_alloc_rq_maps(set);
        if (!err)
            break;

        set->queue_depth >>= 1;
        if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN) {
            err = -ENOMEM;
            break;
        }
    } while (set->queue_depth);

    if (!set->queue_depth || err) {
        pr_err("blk-mq: failed to allocate request map\n");
        return -ENOMEM;
    }

    if (depth != set->queue_depth)
        pr_info("blk-mq: reduced tag depth (%u -> %u)\n",
                        depth, set->queue_depth);

    return 0;
}

/*
 * Alloc a tag set to be associated with one or more request queues.
 * May fail with EINVAL for various error conditions. May adjust the
 * requested depth down, if it's too large. In that case, the set
 * value will be stored in set->queue_depth.
 */
int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set)
{
    int i, ret;

    BUILD_BUG_ON(BLK_MQ_MAX_DEPTH > 1 << BLK_MQ_UNIQUE_TAG_BITS);

    if (!set->nr_hw_queues)
        return -EINVAL;
    if (!set->queue_depth)
        return -EINVAL;
    if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN)
        return -EINVAL;

    if (!set->ops->queue_rq)
        return -EINVAL;

    if (!set->ops->get_budget ^ !set->ops->put_budget)
        return -EINVAL;

    if (set->queue_depth > BLK_MQ_MAX_DEPTH) {
        pr_info("blk-mq: reduced tag depth to %u\n",
            BLK_MQ_MAX_DEPTH);
        set->queue_depth = BLK_MQ_MAX_DEPTH;
    }

    if (!set->nr_maps)
        set->nr_maps = 1;
    else if (set->nr_maps > HCTX_MAX_TYPES)
        return -EINVAL;

    /*
     * If a crashdump is active, then we are potentially in a very
     * memory constrained environment. Limit us to  64 tags to prevent
     * using too much memory.
     */
    if (is_kdump_kernel())
        set->queue_depth = min(64U, set->queue_depth);

    /*
     * There is no use for more h/w queues than cpus if we just have
     * a single map
     */
    if (set->nr_maps == 1 && set->nr_hw_queues > nr_cpu_ids)
        set->nr_hw_queues = nr_cpu_ids;

    if (set->flags & BLK_MQ_F_BLOCKING) {
        set->srcu = kmalloc(sizeof(*set->srcu), GFP_KERNEL);
        if (!set->srcu)
            return -ENOMEM;
        ret = init_srcu_struct(set->srcu);
        if (ret)
            goto out_free_srcu;
    }

    ret = -ENOMEM;
    set->tags = kcalloc_node(set->nr_hw_queues,
                 sizeof(struct blk_mq_tags *), GFP_KERNEL,
                 set->numa_node);
    if (!set->tags)
        goto out_cleanup_srcu;

    for (i = 0; i < set->nr_maps; i++) {
        set->map[i].mq_map = kcalloc_node(nr_cpu_ids,
                          sizeof(set->map[i].mq_map[0]),
                          GFP_KERNEL, set->numa_node);
        if (!set->map[i].mq_map)
            goto out_free_mq_map;
        set->map[i].nr_queues = set->nr_hw_queues;
    }

    blk_mq_update_queue_map(set);

    ret = blk_mq_alloc_set_map_and_rqs(set);
    if (ret)
        goto out_free_mq_map;

    mutex_init(&set->tag_list_lock);
    INIT_LIST_HEAD(&set->tag_list);

    return 0;

out_free_mq_map:
    for (i = 0; i < set->nr_maps; i++) {
        kfree(set->map[i].mq_map);
        set->map[i].mq_map = NULL;
    }
    kfree(set->tags);
    set->tags = NULL;
out_cleanup_srcu:
    if (set->flags & BLK_MQ_F_BLOCKING)
        cleanup_srcu_struct(set->srcu);
out_free_srcu:
    if (set->flags & BLK_MQ_F_BLOCKING)
        kfree(set->srcu);
    return ret;
}

struct gendisk *__blk_mq_alloc_disk(struct blk_mq_tag_set *set,
        struct queue_limits *lim, void *queuedata,
        struct lock_class_key *lkclass)
{
    struct request_queue *q;
    struct gendisk *disk;

    q = blk_mq_alloc_queue(set, lim, queuedata);
    if (IS_ERR(q))
        return ERR_CAST(q);

    disk = __alloc_disk_node(q, set->numa_node, lkclass);
    if (!disk) {
        blk_mq_destroy_queue(q);
        blk_put_queue(q);
        return ERR_PTR(-ENOMEM);
    }
    set_bit(GD_OWNS_QUEUE, &disk->state);
    return disk;
}

struct request_queue *blk_mq_alloc_queue(struct blk_mq_tag_set *set,
        struct queue_limits *lim, void *queuedata)
{
    struct queue_limits default_lim = { };
    struct request_queue *q;
    int ret;

    if (!lim)
        lim = &default_lim;
    lim->features |= BLK_FEAT_IO_STAT | BLK_FEAT_NOWAIT;
    if (set->nr_maps > HCTX_TYPE_POLL)
        lim->features |= BLK_FEAT_POLL;

    q = blk_alloc_queue(lim, set->numa_node);
    if (IS_ERR(q))
        return q;
    q->queuedata = queuedata;
    ret = blk_mq_init_allocated_queue(set, q);
    if (ret) {
        blk_put_queue(q);
        return ERR_PTR(ret);
    }
    return q;
}

/* All allocations will be freed in release handler of q->mq_kobj */
static int blk_mq_alloc_ctxs(struct request_queue *q)
{
    struct blk_mq_ctxs *ctxs;
    int cpu;

    ctxs = kzalloc(sizeof(*ctxs), GFP_KERNEL);
    if (!ctxs)
        return -ENOMEM;

    ctxs->queue_ctx = alloc_percpu(struct blk_mq_ctx);
    if (!ctxs->queue_ctx)
        goto fail;

    for_each_possible_cpu(cpu) {
        struct blk_mq_ctx *ctx = per_cpu_ptr(ctxs->queue_ctx, cpu);
        ctx->ctxs = ctxs;
    }

    q->mq_kobj = &ctxs->kobj;
    q->queue_ctx = ctxs->queue_ctx;

    return 0;
 fail:
    kfree(ctxs);
    return -ENOMEM;
}

int blk_mq_init_allocated_queue(struct blk_mq_tag_set *set,
        struct request_queue *q)
{
    pr_err("%s: No impl.", __func__);

    /* mark the queue as mq asap */
    q->mq_ops = set->ops;

    /*
     * ->tag_set has to be setup before initialize hctx, which cpuphp
     * handler needs it for checking queue mapping
     */
    q->tag_set = set;

    if (blk_mq_alloc_ctxs(q))
        goto err_exit;

    /* init q->mq_kobj and sw queues' kobjects */
    //blk_mq_sysfs_init(q);

    INIT_LIST_HEAD(&q->unused_hctx_list);
    spin_lock_init(&q->unused_hctx_lock);

    xa_init(&q->hctx_table);

#if 0
    blk_mq_realloc_hw_ctxs(set, q);
    if (!q->nr_hw_queues)
        goto err_hctxs;

    INIT_WORK(&q->timeout_work, blk_mq_timeout_work);
    blk_queue_rq_timeout(q, set->timeout ? set->timeout : 30 * HZ);
#endif

    q->queue_flags |= QUEUE_FLAG_MQ_DEFAULT;

    //INIT_DELAYED_WORK(&q->requeue_work, blk_mq_requeue_work);
    INIT_LIST_HEAD(&q->flush_list);
    INIT_LIST_HEAD(&q->requeue_list);
    spin_lock_init(&q->requeue_lock);

    q->nr_requests = set->queue_depth;

#if 0
    blk_mq_init_cpu_queues(q, set->nr_hw_queues);
    blk_mq_add_queue_tag_set(set, q);
    blk_mq_map_swqueue(q);
#endif
    return 0;

err_hctxs:
    blk_mq_release(q);
err_exit:
    q->mq_ops = NULL;
    return -ENOMEM;
}

/*
 * Check if there is a suitable cached request and return it.
 */
static struct request *blk_mq_peek_cached_request(struct blk_plug *plug,
        struct request_queue *q, blk_opf_t opf)
{
    enum hctx_type type = blk_mq_get_hctx_type(opf);
    struct request *rq;

    if (!plug)
        return NULL;
    rq = rq_list_peek(&plug->cached_rqs);
    if (!rq || rq->q != q)
        return NULL;
    if (type != rq->mq_hctx->type &&
        (type != HCTX_TYPE_READ || rq->mq_hctx->type != HCTX_TYPE_DEFAULT))
        return NULL;
    if (op_is_flush(rq->cmd_flags) != op_is_flush(opf))
        return NULL;
    return rq;
}

static bool bio_unaligned(const struct bio *bio, struct request_queue *q)
{
    unsigned int bs_mask = queue_logical_block_size(q) - 1;

    /* .bi_sector of any zero sized bio need to be initialized */
    if ((bio->bi_iter.bi_size & bs_mask) ||
        ((bio->bi_iter.bi_sector << SECTOR_SHIFT) & bs_mask))
        return true;
    return false;
}

/**
 * blk_mq_submit_bio - Create and send a request to block device.
 * @bio: Bio pointer.
 *
 * Builds up a request structure from @q and @bio and send to the device. The
 * request may not be queued directly to hardware if:
 * * This request can be merged with another one
 * * We want to place request at plug queue for possible future merging
 * * There is an IO scheduler active at this queue
 *
 * It will not queue the request if there is an error with the bio, or at the
 * request creation.
 */
void blk_mq_submit_bio(struct bio *bio)
{
    struct request_queue *q = bdev_get_queue(bio->bi_bdev);
    struct blk_plug *plug = current->plug;
    const int is_sync = op_is_sync(bio->bi_opf);
    struct blk_mq_hw_ctx *hctx;
    unsigned int nr_segs;
    struct request *rq;
    blk_status_t ret;

    /*
     * If the plug has a cached request for this queue, try to use it.
     */
    rq = blk_mq_peek_cached_request(plug, q, bio->bi_opf);

    /*
     * A BIO that was released from a zone write plug has already been
     * through the preparation in this function, already holds a reference
     * on the queue usage counter, and is the only write BIO in-flight for
     * the target zone. Go straight to preparing a request for it.
     */
    if (bio_zone_write_plugging(bio)) {
        nr_segs = bio->__bi_nr_segments;
        if (rq)
            blk_queue_exit(q);
        goto new_request;
    }

    bio = blk_queue_bounce(bio, q);

    /*
     * The cached request already holds a q_usage_counter reference and we
     * don't have to acquire a new one if we use it.
     */
    if (!rq) {
#if 0
        if (unlikely(bio_queue_enter(bio)))
            return;
#endif
        pr_err("%s: No bio_queue_enter\n", __func__);
    }
    printk("%s: step1\n", __func__);

    /*
     * Device reconfiguration may change logical block size or reduce the
     * number of poll queues, so the checks for alignment and poll support
     * have to be done with queue usage counter held.
     */
    if (unlikely(bio_unaligned(bio, q))) {
        bio_io_error(bio);
        goto queue_exit;
    }

    if ((bio->bi_opf & REQ_POLLED) && !blk_mq_can_poll(q)) {
        bio->bi_status = BLK_STS_NOTSUPP;
        bio_endio(bio);
        goto queue_exit;
    }

    bio = __bio_split_to_limits(bio, &q->limits, &nr_segs);
    if (!bio)
        goto queue_exit;

    if (!bio_integrity_prep(bio))
        goto queue_exit;

#if 0
    if (blk_mq_attempt_bio_merge(q, bio, nr_segs))
        goto queue_exit;

    if (blk_queue_is_zoned(q) && blk_zone_plug_bio(bio, nr_segs))
        goto queue_exit;
#endif

    PANIC("stage 1");
new_request:
    PANIC("new_request");
#if 0
    if (!rq) {
        rq = blk_mq_get_new_requests(q, plug, bio, nr_segs);
        if (unlikely(!rq))
            goto queue_exit;
    } else {
        blk_mq_use_cached_rq(rq, plug, bio);
    }

    trace_block_getrq(bio);

    rq_qos_track(q, rq, bio);

    blk_mq_bio_to_request(rq, bio, nr_segs);

    ret = blk_crypto_rq_get_keyslot(rq);
    if (ret != BLK_STS_OK) {
        bio->bi_status = ret;
        bio_endio(bio);
        blk_mq_free_request(rq);
        return;
    }

    if (bio_zone_write_plugging(bio))
        blk_zone_write_plug_init_request(rq);

    if (op_is_flush(bio->bi_opf) && blk_insert_flush(rq))
        return;

    if (plug) {
        blk_add_rq_to_plug(plug, rq);
        return;
    }

    hctx = rq->mq_hctx;
    if ((rq->rq_flags & RQF_USE_SCHED) ||
        (hctx->dispatch_busy && (q->nr_hw_queues == 1 || !is_sync))) {
        blk_mq_insert_request(rq, 0);
        blk_mq_run_hw_queue(hctx, true);
    } else {
        blk_mq_run_dispatch_ops(q, blk_mq_try_issue_directly(hctx, rq));
    }
#endif

    PANIC("");
    return;

queue_exit:
    /*
     * Don't drop the queue reference if we were trying to use a cached
     * request and thus didn't acquire one.
     */
    if (!rq)
        blk_queue_exit(q);

    PANIC("ERR");
}
