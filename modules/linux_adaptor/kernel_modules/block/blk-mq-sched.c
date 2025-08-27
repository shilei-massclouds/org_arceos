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

/*
 * Mark a hardware queue as needing a restart.
 */
void blk_mq_sched_mark_restart_hctx(struct blk_mq_hw_ctx *hctx)
{
    if (test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
        return;

    set_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);
}

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

void __blk_mq_sched_restart(struct blk_mq_hw_ctx *hctx)
{
    clear_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);

    /*
     * Order clearing SCHED_RESTART and list_empty_careful(&hctx->dispatch)
     * in blk_mq_run_hw_queue(). Its pair is the barrier in
     * blk_mq_dispatch_rq_list(). So dispatch code won't see SCHED_RESTART,
     * meantime new request added to hctx->dispatch is missed to check in
     * blk_mq_run_hw_queue().
     */
    smp_mb();

    blk_mq_run_hw_queue(hctx, true);
}

#define BLK_MQ_BUDGET_DELAY 3       /* ms units */

/*
 * Only SCSI implements .get_budget and .put_budget, and SCSI restarts
 * its queue by itself in its completion handler, so we don't need to
 * restart queue if .get_budget() fails to get the budget.
 *
 * Returns -EAGAIN if hctx->dispatch was found non-empty and run_work has to
 * be run again.  This is necessary to avoid starving flushes.
 */
static int __blk_mq_do_dispatch_sched(struct blk_mq_hw_ctx *hctx)
{
    PANIC("");
}

static int blk_mq_do_dispatch_sched(struct blk_mq_hw_ctx *hctx)
{
    unsigned long end = jiffies + HZ;
    int ret;

    do {
        ret = __blk_mq_do_dispatch_sched(hctx);
        if (ret != 1)
            break;
        if (need_resched() || time_is_before_jiffies(end)) {
            blk_mq_delay_run_hw_queue(hctx, 0);
            break;
        }
    } while (1);

    return ret;
}

static struct blk_mq_ctx *blk_mq_next_ctx(struct blk_mq_hw_ctx *hctx,
                      struct blk_mq_ctx *ctx)
{
    unsigned short idx = ctx->index_hw[hctx->type];

    if (++idx == hctx->nr_ctx)
        idx = 0;

    return hctx->ctxs[idx];
}

/*
 * Only SCSI implements .get_budget and .put_budget, and SCSI restarts
 * its queue by itself in its completion handler, so we don't need to
 * restart queue if .get_budget() fails to get the budget.
 *
 * Returns -EAGAIN if hctx->dispatch was found non-empty and run_work has to
 * be run again.  This is necessary to avoid starving flushes.
 */
static int blk_mq_do_dispatch_ctx(struct blk_mq_hw_ctx *hctx)
{
    struct request_queue *q = hctx->queue;
    LIST_HEAD(rq_list);
    struct blk_mq_ctx *ctx = READ_ONCE(hctx->dispatch_from);
    int ret = 0;
    struct request *rq;

    do {
        int budget_token;

        if (!list_empty_careful(&hctx->dispatch)) {
            ret = -EAGAIN;
            break;
        }

        if (!sbitmap_any_bit_set(&hctx->ctx_map))
            break;

        budget_token = blk_mq_get_dispatch_budget(q);
        if (budget_token < 0)
            break;

        rq = blk_mq_dequeue_from_ctx(hctx, ctx);
        if (!rq) {
            blk_mq_put_dispatch_budget(q, budget_token);
            /*
             * We're releasing without dispatching. Holding the
             * budget could have blocked any "hctx"s with the
             * same queue and if we didn't dispatch then there's
             * no guarantee anyone will kick the queue.  Kick it
             * ourselves.
             */
            blk_mq_delay_run_hw_queues(q, BLK_MQ_BUDGET_DELAY);
            break;
        }

        blk_mq_set_rq_budget_token(rq, budget_token);

        /*
         * Now this rq owns the budget which has to be released
         * if this rq won't be queued to driver via .queue_rq()
         * in blk_mq_dispatch_rq_list().
         */
        list_add(&rq->queuelist, &rq_list);

        /* round robin for fair dispatch */
        ctx = blk_mq_next_ctx(hctx, rq->mq_ctx);

        PANIC("");
    } while (blk_mq_dispatch_rq_list(rq->mq_hctx, &rq_list, 1));

    WRITE_ONCE(hctx->dispatch_from, ctx);
    return ret;
}

static int __blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
    bool need_dispatch = false;
    LIST_HEAD(rq_list);

    /*
     * If we have previous entries on our dispatch list, grab them first for
     * more fair dispatch.
     */
    if (!list_empty_careful(&hctx->dispatch)) {
        spin_lock(&hctx->lock);
        if (!list_empty(&hctx->dispatch))
            list_splice_init(&hctx->dispatch, &rq_list);
        spin_unlock(&hctx->lock);
    }

    /*
     * Only ask the scheduler for requests, if we didn't have residual
     * requests from the dispatch list. This is to avoid the case where
     * we only ever dispatch a fraction of the requests available because
     * of low device queue depth. Once we pull requests out of the IO
     * scheduler, we can no longer merge or sort them. So it's best to
     * leave them there for as long as we can. Mark the hw queue as
     * needing a restart in that case.
     *
     * We want to dispatch from the scheduler if there was nothing
     * on the dispatch list or we were able to dispatch from the
     * dispatch list.
     */
    if (!list_empty(&rq_list)) {
        blk_mq_sched_mark_restart_hctx(hctx);
        if (!blk_mq_dispatch_rq_list(hctx, &rq_list, 0))
            return 0;
        need_dispatch = true;
    } else {
        need_dispatch = hctx->dispatch_busy;
    }

    if (hctx->queue->elevator)
        return blk_mq_do_dispatch_sched(hctx);

    /* dequeue request one by one from sw queue if queue is busy */
    if (need_dispatch)
        return blk_mq_do_dispatch_ctx(hctx);
    blk_mq_flush_busy_ctxs(hctx, &rq_list);
    blk_mq_dispatch_rq_list(hctx, &rq_list, 0);
    return 0;
}

void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
    struct request_queue *q = hctx->queue;

    /* RCU or SRCU read lock is needed before checking quiesced flag */
    if (unlikely(blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)))
        return;

    /*
     * A return of -EAGAIN is an indication that hctx->dispatch is not
     * empty and we must run again in order to avoid starving flushes.
     */
    if (__blk_mq_sched_dispatch_requests(hctx) == -EAGAIN) {
        if (__blk_mq_sched_dispatch_requests(hctx) == -EAGAIN)
            blk_mq_run_hw_queue(hctx, true);
    }
}
