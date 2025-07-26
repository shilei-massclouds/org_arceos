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
    pr_err("%s: No impl.", __func__);
}
