#include <linux/printk.h>
#include <linux/workqueue.h>
#include <linux/slab.h>

#include "booter.h"

struct workqueue_struct {
};

struct workqueue_struct *
alloc_workqueue(const char *fmt,
                unsigned int flags,
                int max_active, ...)
{
    struct workqueue_struct *wq;

    printk("%s: ...\n", __func__);
    return NULL;

    /*
    wq = kzalloc(sizeof(*wq), GFP_KERNEL);
    if (!wq)
        return NULL;

    return wq;
    */
}

/**
 * queue_work_on - queue work on specific cpu
 * @cpu: CPU number to execute work on
 * @wq: workqueue to use
 * @work: work to queue
 *
 * We queue the work to a specific CPU, the caller must ensure it
 * can't go away.
 *
 * Return: %false if @work was already on a queue, %true otherwise.
 */
bool queue_work_on(int cpu, struct workqueue_struct *wq,
           struct work_struct *work)
{
    booter_panic("No impl.\n");
}

/**
 * flush_work - wait for a work to finish executing the last queueing instance
 * @work: the work to flush
 *
 * Wait until @work has finished execution.  @work is guaranteed to be idle
 * on return if it hasn't been requeued since flush started.
 *
 * Return:
 * %true if flush_work() waited for the work to finish execution,
 * %false if it was already idle.
 */
bool flush_work(struct work_struct *work)
{
    booter_panic("No impl.\n");
}

/**
 * destroy_workqueue - safely terminate a workqueue
 * @wq: target workqueue
 *
 * Safely destroy a workqueue. All work currently pending will be done first.
 */
void destroy_workqueue(struct workqueue_struct *wq)
{
    booter_panic("No impl.\n");
}
