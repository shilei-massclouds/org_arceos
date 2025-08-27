/*
 * Functions related to generic timeout handling of requests.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/fault-inject.h>

#include "blk.h"
#include "blk-mq.h"

#include "../adaptor.h"

static unsigned long blk_timeout_mask __read_mostly;

/*
 * Just a rough estimate, we don't care about specific values for timeouts.
 */
static inline unsigned long blk_round_jiffies(unsigned long j)
{
    return (j + blk_timeout_mask) + 1;
}

unsigned long blk_rq_timeout(unsigned long timeout)
{
    unsigned long maxt;

    maxt = blk_round_jiffies(jiffies + BLK_MAX_TIMEOUT);
    if (time_after(timeout, maxt))
        timeout = maxt;

    return timeout;
}

/**
 * blk_add_timer - Start timeout timer for a single request
 * @req:    request that is about to start running.
 *
 * Notes:
 *    Each request has its own timer, and as it is added to the queue, we
 *    set up the timer. When the request completes, we cancel the timer.
 */
void blk_add_timer(struct request *req)
{
    struct request_queue *q = req->q;
    unsigned long expiry;

    /*
     * Some LLDs, like scsi, peek at the timeout to prevent a
     * command from being retried forever.
     */
    if (!req->timeout)
        req->timeout = q->rq_timeout;

    req->rq_flags &= ~RQF_TIMED_OUT;

    expiry = jiffies + req->timeout;
    WRITE_ONCE(req->deadline, expiry);

    /*
     * If the timer isn't already pending or this timeout is earlier
     * than an existing one, modify the timer. Round up to next nearest
     * second.
     */
    expiry = blk_rq_timeout(blk_round_jiffies(expiry));

    if (!timer_pending(&q->timeout) ||
        time_before(expiry, q->timeout.expires)) {
        unsigned long diff = q->timeout.expires - expiry;

        /*
         * Due to added timer slack to group timers, the timer
         * will often be a little in front of what we asked for.
         * So apply some tolerance here too, otherwise we keep
         * modifying the timer because expires for value X
         * will be X + something.
         */
        if (!timer_pending(&q->timeout) || (diff >= HZ / 2))
            mod_timer(&q->timeout, expiry);
    }
}

static int __init blk_timeout_init(void)
{
    blk_timeout_mask = roundup_pow_of_two(HZ) - 1;
    return 0;
}

void cl_blk_timeout_init(void)
{
    blk_timeout_init();
}
