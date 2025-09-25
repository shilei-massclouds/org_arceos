#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/delay.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"

#include "../adaptor.h"

/*
 * Recalculate wakeup batch when tag is shared by hctx.
 */
static void blk_mq_update_wake_batch(struct blk_mq_tags *tags,
        unsigned int users)
{
    if (!users)
        return;

    sbitmap_queue_recalculate_wake_batch(&tags->bitmap_tags,
            users);
    sbitmap_queue_recalculate_wake_batch(&tags->breserved_tags,
            users);
}

static int bt_alloc(struct sbitmap_queue *bt, unsigned int depth,
            bool round_robin, int node)
{
    return sbitmap_queue_init_node(bt, depth, -1, round_robin, GFP_KERNEL,
                       node);
}

int blk_mq_init_bitmaps(struct sbitmap_queue *bitmap_tags,
            struct sbitmap_queue *breserved_tags,
            unsigned int queue_depth, unsigned int reserved,
            int node, int alloc_policy)
{
    unsigned int depth = queue_depth - reserved;
    bool round_robin = alloc_policy == BLK_TAG_ALLOC_RR;

    if (bt_alloc(bitmap_tags, depth, round_robin, node))
        return -ENOMEM;
    if (bt_alloc(breserved_tags, reserved, round_robin, node))
        goto free_bitmap_tags;

    return 0;

free_bitmap_tags:
    sbitmap_queue_free(bitmap_tags);
    return -ENOMEM;
}

struct blk_mq_tags *blk_mq_init_tags(unsigned int total_tags,
                     unsigned int reserved_tags,
                     int node, int alloc_policy)
{
    struct blk_mq_tags *tags;

    if (total_tags > BLK_MQ_TAG_MAX) {
        pr_err("blk-mq: tag depth too large\n");
        return NULL;
    }

    tags = kzalloc_node(sizeof(*tags), GFP_KERNEL, node);
    if (!tags)
        return NULL;

    tags->nr_tags = total_tags;
    tags->nr_reserved_tags = reserved_tags;
    spin_lock_init(&tags->lock);

    if (blk_mq_init_bitmaps(&tags->bitmap_tags, &tags->breserved_tags,
                total_tags, reserved_tags, node,
                alloc_policy) < 0) {
        kfree(tags);
        return NULL;
    }
    return tags;
}

void blk_mq_free_tags(struct blk_mq_tags *tags)
{
    sbitmap_queue_free(&tags->bitmap_tags);
    sbitmap_queue_free(&tags->breserved_tags);
    kfree(tags);
}

static int __blk_mq_get_tag(struct blk_mq_alloc_data *data,
                struct sbitmap_queue *bt)
{
    if (!data->q->elevator && !(data->flags & BLK_MQ_REQ_RESERVED) &&
            !hctx_may_queue(data->hctx, bt))
        return BLK_MQ_NO_TAG;

    if (data->shallow_depth)
        return sbitmap_queue_get_shallow(bt, data->shallow_depth);
    else
        return __sbitmap_queue_get(bt);
}

unsigned int blk_mq_get_tag(struct blk_mq_alloc_data *data)
{
    struct blk_mq_tags *tags = blk_mq_tags_from_data(data);
    struct sbitmap_queue *bt;
    struct sbq_wait_state *ws;
    DEFINE_SBQ_WAIT(wait);
    unsigned int tag_offset;
    int tag;

    if (data->flags & BLK_MQ_REQ_RESERVED) {
        if (unlikely(!tags->nr_reserved_tags)) {
            WARN_ON_ONCE(1);
            return BLK_MQ_NO_TAG;
        }
        bt = &tags->breserved_tags;
        tag_offset = 0;
    } else {
        bt = &tags->bitmap_tags;
        tag_offset = tags->nr_reserved_tags;
    }

    tag = __blk_mq_get_tag(data, bt);
    if (tag != BLK_MQ_NO_TAG)
        goto found_tag;

    if (data->flags & BLK_MQ_REQ_NOWAIT)
        return BLK_MQ_NO_TAG;

    ws = bt_wait_ptr(bt, data->hctx);
    do {
        struct sbitmap_queue *bt_prev;

        /*
         * We're out of tags on this hardware queue, kick any
         * pending IO submits before going to sleep waiting for
         * some to complete.
         */
        blk_mq_run_hw_queue(data->hctx, false);

        /*
         * Retry tag allocation after running the hardware queue,
         * as running the queue may also have found completions.
         */
        tag = __blk_mq_get_tag(data, bt);
        if (tag != BLK_MQ_NO_TAG)
            break;

        sbitmap_prepare_to_wait(bt, ws, &wait, TASK_UNINTERRUPTIBLE);

        tag = __blk_mq_get_tag(data, bt);
        if (tag != BLK_MQ_NO_TAG)
            break;

        bt_prev = bt;
        io_schedule();

        sbitmap_finish_wait(bt, ws, &wait);

        data->ctx = blk_mq_get_ctx(data->q);
        data->hctx = blk_mq_map_queue(data->q, data->cmd_flags,
                        data->ctx);
        tags = blk_mq_tags_from_data(data);
        if (data->flags & BLK_MQ_REQ_RESERVED)
            bt = &tags->breserved_tags;
        else
            bt = &tags->bitmap_tags;

        /*
         * If destination hw queue is changed, fake wake up on
         * previous queue for compensating the wake up miss, so
         * other allocations on previous queue won't be starved.
         */
        if (bt != bt_prev)
            sbitmap_queue_wake_up(bt_prev, 1);

        ws = bt_wait_ptr(bt, data->hctx);
    } while (1);

    sbitmap_finish_wait(bt, ws, &wait);

found_tag:
    /*
     * Give up this allocation if the hctx is inactive.  The caller will
     * retry on an active hctx.
     */
    if (unlikely(test_bit(BLK_MQ_S_INACTIVE, &data->hctx->state))) {
        blk_mq_put_tag(tags, data->ctx, tag + tag_offset);
        return BLK_MQ_NO_TAG;
    }
    return tag + tag_offset;
}

void blk_mq_put_tag(struct blk_mq_tags *tags, struct blk_mq_ctx *ctx,
            unsigned int tag)
{
    if (!blk_mq_tag_is_reserved(tags, tag)) {
        const int real_tag = tag - tags->nr_reserved_tags;

        BUG_ON(real_tag >= tags->nr_tags);
        sbitmap_queue_clear(&tags->bitmap_tags, real_tag, ctx->cpu);
    } else {
        sbitmap_queue_clear(&tags->breserved_tags, tag, ctx->cpu);
    }
}

void blk_mq_put_tags(struct blk_mq_tags *tags, int *tag_array, int nr_tags)
{
    sbitmap_queue_clear_batch(&tags->bitmap_tags, tags->nr_reserved_tags,
                    tag_array, nr_tags);
}

struct bt_iter_data {
    struct blk_mq_hw_ctx *hctx;
    struct request_queue *q;
    busy_tag_iter_fn *fn;
    void *data;
    bool reserved;
};

static struct request *blk_mq_find_and_get_req(struct blk_mq_tags *tags,
        unsigned int bitnr)
{
    struct request *rq;
    unsigned long flags;

    spin_lock_irqsave(&tags->lock, flags);
    rq = tags->rqs[bitnr];
    if (!rq || rq->tag != bitnr || !req_ref_inc_not_zero(rq))
        rq = NULL;
    spin_unlock_irqrestore(&tags->lock, flags);
    return rq;
}

static bool bt_iter(struct sbitmap *bitmap, unsigned int bitnr, void *data)
{
    struct bt_iter_data *iter_data = data;
    struct blk_mq_hw_ctx *hctx = iter_data->hctx;
    struct request_queue *q = iter_data->q;
    struct blk_mq_tag_set *set = q->tag_set;
    struct blk_mq_tags *tags;
    struct request *rq;
    bool ret = true;

    if (blk_mq_is_shared_tags(set->flags))
        tags = set->shared_tags;
    else
        tags = hctx->tags;

    if (!iter_data->reserved)
        bitnr += tags->nr_reserved_tags;
    /*
     * We can hit rq == NULL here, because the tagging functions
     * test and set the bit before assigning ->rqs[].
     */
    rq = blk_mq_find_and_get_req(tags, bitnr);
    if (!rq)
        return true;

    if (rq->q == q && (!hctx || rq->mq_hctx == hctx))
        ret = iter_data->fn(rq, iter_data->data);
    blk_mq_put_rq_ref(rq);
    return ret;
}

/**
 * bt_for_each - iterate over the requests associated with a hardware queue
 * @hctx:   Hardware queue to examine.
 * @q:      Request queue to examine.
 * @bt:     sbitmap to examine. This is either the breserved_tags member
 *      or the bitmap_tags member of struct blk_mq_tags.
 * @fn:     Pointer to the function that will be called for each request
 *      associated with @hctx that has been assigned a driver tag.
 *      @fn will be called as follows: @fn(@hctx, rq, @data, @reserved)
 *      where rq is a pointer to a request. Return true to continue
 *      iterating tags, false to stop.
 * @data:   Will be passed as third argument to @fn.
 * @reserved:   Indicates whether @bt is the breserved_tags member or the
 *      bitmap_tags member of struct blk_mq_tags.
 */
static void bt_for_each(struct blk_mq_hw_ctx *hctx, struct request_queue *q,
            struct sbitmap_queue *bt, busy_tag_iter_fn *fn,
            void *data, bool reserved)
{
    struct bt_iter_data iter_data = {
        .hctx = hctx,
        .fn = fn,
        .data = data,
        .reserved = reserved,
        .q = q,
    };

    sbitmap_for_each_set(&bt->sb, bt_iter, &iter_data);
}

void blk_mq_tag_update_sched_shared_tags(struct request_queue *q)
{
    sbitmap_queue_resize(&q->sched_shared_tags->bitmap_tags,
                 q->nr_requests - q->tag_set->reserved_tags);
}

/**
 * blk_mq_queue_tag_busy_iter - iterate over all requests with a driver tag
 * @q:      Request queue to examine.
 * @fn:     Pointer to the function that will be called for each request
 *      on @q. @fn will be called as follows: @fn(hctx, rq, @priv,
 *      reserved) where rq is a pointer to a request and hctx points
 *      to the hardware queue associated with the request. 'reserved'
 *      indicates whether or not @rq is a reserved request.
 * @priv:   Will be passed as third argument to @fn.
 *
 * Note: if @q->tag_set is shared with other request queues then @fn will be
 * called for all requests on all queues that share that tag set and not only
 * for requests associated with @q.
 */
void blk_mq_queue_tag_busy_iter(struct request_queue *q, busy_tag_iter_fn *fn,
        void *priv)
{
#if 0
    /*
     * __blk_mq_update_nr_hw_queues() updates nr_hw_queues and hctx_table
     * while the queue is frozen. So we can use q_usage_counter to avoid
     * racing with it.
     */
    if (!percpu_ref_tryget(&q->q_usage_counter))
        return;
#endif

    if (blk_mq_is_shared_tags(q->tag_set->flags)) {
        struct blk_mq_tags *tags = q->tag_set->shared_tags;
        struct sbitmap_queue *bresv = &tags->breserved_tags;
        struct sbitmap_queue *btags = &tags->bitmap_tags;

        if (tags->nr_reserved_tags)
            bt_for_each(NULL, q, bresv, fn, priv, true);
        bt_for_each(NULL, q, btags, fn, priv, false);
    } else {
        struct blk_mq_hw_ctx *hctx;
        unsigned long i;

        queue_for_each_hw_ctx(q, hctx, i) {
            struct blk_mq_tags *tags = hctx->tags;
            struct sbitmap_queue *bresv = &tags->breserved_tags;
            struct sbitmap_queue *btags = &tags->bitmap_tags;

            /*
             * If no software queues are currently mapped to this
             * hardware queue, there's nothing to check
             */
            if (!blk_mq_hw_queue_mapped(hctx))
                continue;

            if (tags->nr_reserved_tags)
                bt_for_each(hctx, q, bresv, fn, priv, true);
            bt_for_each(hctx, q, btags, fn, priv, false);
        }
    }
    blk_queue_exit(q);
}

/*
 * If a previously busy queue goes inactive, potential waiters could now
 * be allowed to queue. Wake them up and check.
 */
void __blk_mq_tag_idle(struct blk_mq_hw_ctx *hctx)
{
    struct blk_mq_tags *tags = hctx->tags;
    unsigned int users;

    if (blk_mq_is_shared_tags(hctx->flags)) {
        struct request_queue *q = hctx->queue;

        if (!test_and_clear_bit(QUEUE_FLAG_HCTX_ACTIVE,
                    &q->queue_flags))
            return;
    } else {
        if (!test_and_clear_bit(BLK_MQ_S_TAG_ACTIVE, &hctx->state))
            return;
    }

    spin_lock_irq(&tags->lock);
    users = tags->active_queues - 1;
    WRITE_ONCE(tags->active_queues, users);
    blk_mq_update_wake_batch(tags, users);
    spin_unlock_irq(&tags->lock);

    blk_mq_tag_wakeup_all(tags, false);
}

/*
 * Wakeup all potentially sleeping on tags
 */
void blk_mq_tag_wakeup_all(struct blk_mq_tags *tags, bool include_reserve)
{
    sbitmap_queue_wake_all(&tags->bitmap_tags);
    if (include_reserve)
        sbitmap_queue_wake_all(&tags->breserved_tags);
}
