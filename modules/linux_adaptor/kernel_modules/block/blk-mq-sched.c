/*
 * blk-mq scheduling framework
 *
 * Copyright (C) 2016 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list_sort.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-sched.h"
#include "blk-wbt.h"

#include "../adaptor.h"

bool blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio,
        unsigned int nr_segs)
{
    struct elevator_queue *e = q->elevator;
    struct blk_mq_ctx *ctx;
    struct blk_mq_hw_ctx *hctx;
    bool ret = false;
    enum hctx_type type;

    if (e && e->type->ops.bio_merge) {
        ret = e->type->ops.bio_merge(q, bio, nr_segs);
        goto out_put;
    }

    ctx = blk_mq_get_ctx(q);
    hctx = blk_mq_map_queue(q, bio->bi_opf, ctx);
    printk("%s: ctx(%lx) hctx(%lx)\n", __func__, ctx, hctx);
    type = hctx->type;
    if (!(hctx->flags & BLK_MQ_F_SHOULD_MERGE) ||
        list_empty_careful(&ctx->rq_lists[type]))
        goto out_put;

    /* default per sw-queue merge */
    spin_lock(&ctx->lock);
    /*
     * Reverse check our software queue for entries that we could
     * potentially merge with. Currently includes a hand-wavy stop
     * count of 8, to not spend too much time checking for merges.
     */
    if (blk_bio_list_merge(q, &ctx->rq_lists[type], bio, nr_segs))
        ret = true;

    spin_unlock(&ctx->lock);
out_put:
    return ret;
}
