#include <linux/jiffies.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include <linux/timer.h>

#include "internals.h"

#include "../adaptor.h"

/*
 * We wait here for a poller to finish.
 *
 * If the poll runs on this CPU, then we yell loudly and return
 * false. That will leave the interrupt line disabled in the worst
 * case, but it should never happen.
 *
 * We wait until the poller is done and then recheck disabled and
 * action (about to be disabled). Only if it's still active, we return
 * true and let the handler run.
 */
bool irq_wait_for_poll(struct irq_desc *desc)
    __must_hold(&desc->lock)
{
#if 0
    if (WARN_ONCE(irq_poll_cpu == smp_processor_id(),
              "irq poll in progress on cpu %d for irq %d\n",
              smp_processor_id(), desc->irq_data.irq))
        return false;

#ifdef CONFIG_SMP
    do {
        raw_spin_unlock(&desc->lock);
        while (irqd_irq_inprogress(&desc->irq_data))
            cpu_relax();
        raw_spin_lock(&desc->lock);
    } while (irqd_irq_inprogress(&desc->irq_data));
    /* Might have been disabled in meantime */
    return !irqd_irq_disabled(&desc->irq_data) && desc->action;
#else
    return false;
#endif
#endif
    PANIC("");
}

void note_interrupt(struct irq_desc *desc, irqreturn_t action_ret)
{
    pr_notice("%s: No impl.", __func__);
}
