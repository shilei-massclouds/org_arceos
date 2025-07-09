#include <linux/mm.h>
#include <linux/writeback.h>

#include "booter.h"

/* bdi_wq serves all asynchronous writeback tasks */
struct workqueue_struct *bdi_wq;

/**
 * congestion_wait - wait for a backing_dev to become uncongested
 * @sync: SYNC or ASYNC IO
 * @timeout: timeout in jiffies
 *
 * Waits for up to @timeout jiffies for a backing_dev (any backing_dev) to exit
 * write congestion.  If no backing_devs are congested then just wait for the
 * next write to be completed.
 */
long congestion_wait(int sync, long timeout)
{
    log_error("%s: No impl.\n", __func__);
}

/*
 * This function is used when the first inode for this wb is marked dirty. It
 * wakes-up the corresponding bdi thread which should then take care of the
 * periodic background write-out of dirty inodes. Since the write-out would
 * starts only 'dirty_writeback_interval' centisecs from now anyway, we just
 * set up a timer which wakes the bdi thread up later.
 *
 * Note, we wouldn't bother setting up the timer, but this function is on the
 * fast-path (used by '__mark_inode_dirty()'), so we save few context switches
 * by delaying the wake-up.
 *
 * We have to be careful not to postpone flush work if it is scheduled for
 * earlier. Thus we use queue_delayed_work().
 */
void wb_wakeup_delayed(struct bdi_writeback *wb)
{
#if 0
    unsigned long timeout;

    timeout = msecs_to_jiffies(dirty_writeback_interval * 10);
    spin_lock_bh(&wb->work_lock);
    if (test_bit(WB_registered, &wb->state))
        queue_delayed_work(bdi_wq, &wb->dwork, timeout);
    spin_unlock_bh(&wb->work_lock);
#endif
    struct work_struct *work = &wb->dwork.work;
    if (work == NULL || work->func == NULL) {
        booter_panic("No work.");
    }
    work->func(work);
}
