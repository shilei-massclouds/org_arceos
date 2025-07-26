/*
 * Functions related to segment and merge handling
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/scatterlist.h>
#include <linux/part_stat.h>
#include <linux/blk-cgroup.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"
#include "blk-throttle.h"

#include "../adaptor.h"

/**
 * blk_attempt_plug_merge - try to merge with %current's plugged list
 * @q: request_queue new bio is being queued at
 * @bio: new bio being queued
 * @nr_segs: number of segments in @bio
 * from the passed in @q already in the plug list
 *
 * Determine whether @bio being queued on @q can be merged with the previous
 * request on %current's plugged list.  Returns %true if merge was successful,
 * otherwise %false.
 *
 * Plugging coalesces IOs from the same issuer for the same purpose without
 * going through @q->queue_lock.  As such it's more of an issuing mechanism
 * than scheduling, and the request, while may have elvpriv data, is not
 * added on the elevator at this point.  In addition, we don't have
 * reliable access to the elevator outside queue lock.  Only check basic
 * merging parameters without querying the elevator.
 *
 * Caller must ensure !blk_queue_nomerges(q) beforehand.
 */
bool blk_attempt_plug_merge(struct request_queue *q, struct bio *bio,
        unsigned int nr_segs)
{
    struct blk_plug *plug = current->plug;
    struct request *rq;

    if (!plug || rq_list_empty(&plug->mq_list))
        return false;

#if 0
    rq = plug->mq_list.tail;
    if (rq->q == q)
        return blk_attempt_bio_merge(q, rq, bio, nr_segs, false) ==
            BIO_MERGE_OK;
    else if (!plug->multiple_queues)
        return false;

    rq_list_for_each(&plug->mq_list, rq) {
        if (rq->q != q)
            continue;
        if (blk_attempt_bio_merge(q, rq, bio, nr_segs, false) ==
            BIO_MERGE_OK)
            return true;
        break;
    }
#endif
    PANIC("");
    return false;
}

/*
 * Iterate list of requests and see if we can merge this bio with any
 * of them.
 */
bool blk_bio_list_merge(struct request_queue *q, struct list_head *list,
            struct bio *bio, unsigned int nr_segs)
{
    PANIC("");
}

/*
 * map a request to scatterlist, return number of sg entries setup. Caller
 * must make sure sg can hold rq->nr_phys_segments entries
 */
int __blk_rq_map_sg(struct request_queue *q, struct request *rq,
        struct scatterlist *sglist, struct scatterlist **last_sg)
{
    PANIC("");
}
