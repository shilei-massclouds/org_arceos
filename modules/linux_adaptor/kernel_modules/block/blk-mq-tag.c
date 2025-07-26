#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/delay.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"

#include "../adaptor.h"

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

        PANIC("LOOP");
    } while (1);

    sbitmap_finish_wait(bt, ws, &wait);

    PANIC("");
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
