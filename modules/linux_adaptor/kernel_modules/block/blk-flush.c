#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/gfp.h>
#include <linux/part_stat.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"

#include "../adaptor.h"

/* PREFLUSH/FUA sequences */
enum {
    REQ_FSEQ_PREFLUSH   = (1 << 0), /* pre-flushing in progress */
    REQ_FSEQ_DATA       = (1 << 1), /* data write in progress */
    REQ_FSEQ_POSTFLUSH  = (1 << 2), /* post-flushing in progress */
    REQ_FSEQ_DONE       = (1 << 3),

    REQ_FSEQ_ACTIONS    = REQ_FSEQ_PREFLUSH | REQ_FSEQ_DATA |
                  REQ_FSEQ_POSTFLUSH,

    /*
     * If flush has been pending longer than the following timeout,
     * it's issued even if flush_data requests are still in flight.
     */
    FLUSH_PENDING_TIMEOUT   = 5 * HZ,
};

struct blk_flush_queue *blk_alloc_flush_queue(int node, int cmd_size,
                          gfp_t flags)
{
    struct blk_flush_queue *fq;
    int rq_sz = sizeof(struct request);

    fq = kzalloc_node(sizeof(*fq), flags, node);
    if (!fq)
        goto fail;

    spin_lock_init(&fq->mq_flush_lock);

    rq_sz = round_up(rq_sz + cmd_size, cache_line_size());
    fq->flush_rq = kzalloc_node(rq_sz, flags, node);
    if (!fq->flush_rq)
        goto fail_rq;

    INIT_LIST_HEAD(&fq->flush_queue[0]);
    INIT_LIST_HEAD(&fq->flush_queue[1]);

    return fq;

 fail_rq:
    kfree(fq);
 fail:
    return NULL;
}

static inline struct blk_flush_queue *
blk_get_flush_queue(struct request_queue *q, struct blk_mq_ctx *ctx)
{
    return blk_mq_map_queue(q, REQ_OP_FLUSH, ctx)->fq;
}

static unsigned int blk_flush_cur_seq(struct request *rq)
{
    return 1 << ffz(rq->flush.seq);
}

static void blk_flush_restore_request(struct request *rq)
{
    /*
     * After flush data completion, @rq->bio is %NULL but we need to
     * complete the bio again.  @rq->biotail is guaranteed to equal the
     * original @rq->bio.  Restore it.
     */
    rq->bio = rq->biotail;
    if (rq->bio)
        rq->__sector = rq->bio->bi_iter.bi_sector;

    /* make @rq a normal request */
    rq->rq_flags &= ~RQF_FLUSH_SEQ;
    rq->end_io = rq->flush.saved_end_io;
}

static enum rq_end_io_ret flush_end_io(struct request *flush_rq,
                       blk_status_t error)
{
    PANIC("");
}

/**
 * blk_kick_flush - consider issuing flush request
 * @q: request_queue being kicked
 * @fq: flush queue
 * @flags: cmd_flags of the original request
 *
 * Flush related states of @q have changed, consider issuing flush request.
 * Please read the comment at the top of this file for more info.
 *
 * CONTEXT:
 * spin_lock_irq(fq->mq_flush_lock)
 *
 */
static void blk_kick_flush(struct request_queue *q, struct blk_flush_queue *fq,
               blk_opf_t flags)
{
    struct list_head *pending = &fq->flush_queue[fq->flush_pending_idx];
    struct request *first_rq =
        list_first_entry(pending, struct request, queuelist);
    struct request *flush_rq = fq->flush_rq;

    /* C1 described at the top of this file */
    if (fq->flush_pending_idx != fq->flush_running_idx || list_empty(pending))
        return;

    /* C2 and C3 */
    if (fq->flush_data_in_flight &&
        time_before(jiffies,
            fq->flush_pending_since + FLUSH_PENDING_TIMEOUT))
        return;

    /*
     * Issue flush and toggle pending_idx.  This makes pending_idx
     * different from running_idx, which means flush is in flight.
     */
    fq->flush_pending_idx ^= 1;

    blk_rq_init(q, flush_rq);

    /*
     * In case of none scheduler, borrow tag from the first request
     * since they can't be in flight at the same time. And acquire
     * the tag's ownership for flush req.
     *
     * In case of IO scheduler, flush rq need to borrow scheduler tag
     * just for cheating put/get driver tag.
     */
    flush_rq->mq_ctx = first_rq->mq_ctx;
    flush_rq->mq_hctx = first_rq->mq_hctx;

    if (!q->elevator)
        flush_rq->tag = first_rq->tag;
    else
        flush_rq->internal_tag = first_rq->internal_tag;

    flush_rq->cmd_flags = REQ_OP_FLUSH | REQ_PREFLUSH;
    flush_rq->cmd_flags |= (flags & REQ_DRV) | (flags & REQ_FAILFAST_MASK);
    flush_rq->rq_flags |= RQF_FLUSH_SEQ;
    flush_rq->end_io = flush_end_io;
    /*
     * Order WRITE ->end_io and WRITE rq->ref, and its pair is the one
     * implied in refcount_inc_not_zero() called from
     * blk_mq_find_and_get_req(), which orders WRITE/READ flush_rq->ref
     * and READ flush_rq->end_io
     */
    smp_wmb();
    req_ref_set(flush_rq, 1);

    spin_lock(&q->requeue_lock);
    list_add_tail(&flush_rq->queuelist, &q->flush_list);
    spin_unlock(&q->requeue_lock);

    blk_mq_kick_requeue_list(q);
}

/**
 * blk_flush_complete_seq - complete flush sequence
 * @rq: PREFLUSH/FUA request being sequenced
 * @fq: flush queue
 * @seq: sequences to complete (mask of %REQ_FSEQ_*, can be zero)
 * @error: whether an error occurred
 *
 * @rq just completed @seq part of its flush sequence, record the
 * completion and trigger the next step.
 *
 * CONTEXT:
 * spin_lock_irq(fq->mq_flush_lock)
 */
static void blk_flush_complete_seq(struct request *rq,
                   struct blk_flush_queue *fq,
                   unsigned int seq, blk_status_t error)
{
    struct request_queue *q = rq->q;
    struct list_head *pending = &fq->flush_queue[fq->flush_pending_idx];
    blk_opf_t cmd_flags;

    BUG_ON(rq->flush.seq & seq);
    rq->flush.seq |= seq;
    cmd_flags = rq->cmd_flags;

    if (likely(!error))
        seq = blk_flush_cur_seq(rq);
    else
        seq = REQ_FSEQ_DONE;

    switch (seq) {
    case REQ_FSEQ_PREFLUSH:
    case REQ_FSEQ_POSTFLUSH:
        /* queue for flush */
        if (list_empty(pending))
            fq->flush_pending_since = jiffies;
        list_add_tail(&rq->queuelist, pending);
        break;

    case REQ_FSEQ_DATA:
        fq->flush_data_in_flight++;
        spin_lock(&q->requeue_lock);
        list_move(&rq->queuelist, &q->requeue_list);
        spin_unlock(&q->requeue_lock);
        blk_mq_kick_requeue_list(q);
        break;

    case REQ_FSEQ_DONE:
        /*
         * @rq was previously adjusted by blk_insert_flush() for
         * flush sequencing and may already have gone through the
         * flush data request completion path.  Restore @rq for
         * normal completion and end it.
         */
        list_del_init(&rq->queuelist);
        blk_flush_restore_request(rq);
        blk_mq_end_request(rq, error);
        break;

    default:
        BUG();
    }

    blk_kick_flush(q, fq, cmd_flags);
}

static enum rq_end_io_ret mq_flush_data_end_io(struct request *rq,
                           blk_status_t error)
{
    struct request_queue *q = rq->q;
    struct blk_mq_hw_ctx *hctx = rq->mq_hctx;
    struct blk_mq_ctx *ctx = rq->mq_ctx;
    unsigned long flags;
    struct blk_flush_queue *fq = blk_get_flush_queue(q, ctx);

    if (q->elevator) {
        WARN_ON(rq->tag < 0);
        blk_mq_put_driver_tag(rq);
    }

    /*
     * After populating an empty queue, kick it to avoid stall.  Read
     * the comment in flush_end_io().
     */
    spin_lock_irqsave(&fq->mq_flush_lock, flags);
    fq->flush_data_in_flight--;
    /*
     * May have been corrupted by rq->rq_next reuse, we need to
     * re-initialize rq->queuelist before reusing it here.
     */
    INIT_LIST_HEAD(&rq->queuelist);
    blk_flush_complete_seq(rq, fq, REQ_FSEQ_DATA, error);
    spin_unlock_irqrestore(&fq->mq_flush_lock, flags);

    blk_mq_sched_restart(hctx);
    return RQ_END_IO_NONE;
}

static void blk_rq_init_flush(struct request *rq)
{
    rq->flush.seq = 0;
    rq->rq_flags |= RQF_FLUSH_SEQ;
    rq->flush.saved_end_io = rq->end_io; /* Usually NULL */
    rq->end_io = mq_flush_data_end_io;
}

/*
 * Insert a PREFLUSH/FUA request into the flush state machine.
 * Returns true if the request has been consumed by the flush state machine,
 * or false if the caller should continue to process it.
 */
bool blk_insert_flush(struct request *rq)
{
    struct request_queue *q = rq->q;
    struct blk_flush_queue *fq = blk_get_flush_queue(q, rq->mq_ctx);
    bool supports_fua = q->limits.features & BLK_FEAT_FUA;
    unsigned int policy = 0;

    /* FLUSH/FUA request must never be merged */
    WARN_ON_ONCE(rq->bio != rq->biotail);

    if (blk_rq_sectors(rq))
        policy |= REQ_FSEQ_DATA;

    /*
     * Check which flushes we need to sequence for this operation.
     */
    if (blk_queue_write_cache(q)) {
        if (rq->cmd_flags & REQ_PREFLUSH)
            policy |= REQ_FSEQ_PREFLUSH;
        if ((rq->cmd_flags & REQ_FUA) && !supports_fua)
            policy |= REQ_FSEQ_POSTFLUSH;
    }

    /*
     * @policy now records what operations need to be done.  Adjust
     * REQ_PREFLUSH and FUA for the driver.
     */
    rq->cmd_flags &= ~REQ_PREFLUSH;
    if (!supports_fua)
        rq->cmd_flags &= ~REQ_FUA;

    /*
     * REQ_PREFLUSH|REQ_FUA implies REQ_SYNC, so if we clear any
     * of those flags, we have to set REQ_SYNC to avoid skewing
     * the request accounting.
     */
    rq->cmd_flags |= REQ_SYNC;

    switch (policy) {
    case 0:
        /*
         * An empty flush handed down from a stacking driver may
         * translate into nothing if the underlying device does not
         * advertise a write-back cache.  In this case, simply
         * complete the request.
         */
        blk_mq_end_request(rq, 0);
        return true;
    case REQ_FSEQ_DATA:
        /*
         * If there's data, but no flush is necessary, the request can
         * be processed directly without going through flush machinery.
         * Queue for normal execution.
         */
        return false;
    case REQ_FSEQ_DATA | REQ_FSEQ_POSTFLUSH:
        /*
         * Initialize the flush fields and completion handler to trigger
         * the post flush, and then just pass the command on.
         */
        blk_rq_init_flush(rq);
        rq->flush.seq |= REQ_FSEQ_PREFLUSH;
        spin_lock_irq(&fq->mq_flush_lock);
        fq->flush_data_in_flight++;
        spin_unlock_irq(&fq->mq_flush_lock);
        return false;
    default:
        /*
         * Mark the request as part of a flush sequence and submit it
         * for further processing to the flush state machine.
         */
        blk_rq_init_flush(rq);
        spin_lock_irq(&fq->mq_flush_lock);
        blk_flush_complete_seq(rq, fq, REQ_FSEQ_ACTIONS & ~policy, 0);
        spin_unlock_irq(&fq->mq_flush_lock);
        return true;
    }

    PANIC("");
}
