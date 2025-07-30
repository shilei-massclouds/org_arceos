#include <linux/slab.h>

#include "../adaptor.h"

struct workqueue_struct {
};

__printf(1, 4)
struct workqueue_struct *alloc_workqueue(const char *fmt,
                     unsigned int flags,
                     int max_active, ...)
{
    pr_err("%s: No impl.\n", __func__);
    return kzalloc(sizeof(struct workqueue_struct), GFP_KERNEL);
}

/**
 * queue_delayed_work_on - queue work on specific CPU after delay
 * @cpu: CPU number to execute work on
 * @wq: workqueue to use
 * @dwork: work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * Return: %false if @work was already on a queue, %true otherwise.  If
 * @delay is zero and @dwork is idle, it will be scheduled for immediate
 * execution.
 */
bool queue_delayed_work_on(int cpu, struct workqueue_struct *wq,
               struct delayed_work *dwork, unsigned long delay)
{
    pr_err("%s: No impl.\n", __func__);
    return false;
}

/**
 * mod_delayed_work_on - modify delay of or queue a delayed work on specific CPU
 * @cpu: CPU number to execute work on
 * @wq: workqueue to use
 * @dwork: work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * If @dwork is idle, equivalent to queue_delayed_work_on(); otherwise,
 * modify @dwork's timer so that it expires after @delay.  If @delay is
 * zero, @work is guaranteed to be scheduled immediately regardless of its
 * current state.
 *
 * Return: %false if @dwork was idle and queued, %true if @dwork was
 * pending and its timer was modified.
 *
 * This function is safe to call from any context including IRQ handler.
 * See try_to_grab_pending() for details.
 */
bool mod_delayed_work_on(int cpu, struct workqueue_struct *wq,
             struct delayed_work *dwork, unsigned long delay)
{
    unsigned long flags;
    bool ret = false;
    local_irq_save(flags);
    printk("%s: step1 irq_disabled(%u)\n", __func__, irqs_disabled());

    if (delay == 0) {
        if (dwork == NULL || dwork->work.func == NULL) {
            PANIC("bad dwork.");
        }
        dwork->work.func(&dwork->work);
        /* We must make sure that IRQ disabled. */
        local_irq_disable();
        ret = true;
    } else {
        PANIC("delay is NOT ZERO!");
    }

    printk("%s: step2 irq_disabled(%u)\n", __func__, irqs_disabled());
    local_irq_restore(flags);
    return ret;
}
