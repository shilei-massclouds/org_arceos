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

/*
 * Insert a PREFLUSH/FUA request into the flush state machine.
 * Returns true if the request has been consumed by the flush state machine,
 * or false if the caller should continue to process it.
 */
bool blk_insert_flush(struct request *rq)
{
    PANIC("");
}
