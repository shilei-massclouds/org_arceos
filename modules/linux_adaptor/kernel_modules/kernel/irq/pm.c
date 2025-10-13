#include <linux/irq.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/suspend.h>
#include <linux/syscore_ops.h>

#include "internals.h"
#include "../adaptor.h"

/*
 * Called from __free_irq() with desc->lock held after @action has
 * been removed from the action chain.
 */
void irq_pm_remove_action(struct irq_desc *desc, struct irqaction *action)
{
    desc->nr_actions--;

    if (action->flags & IRQF_FORCE_RESUME)
        desc->force_resume_depth--;

    if (action->flags & IRQF_NO_SUSPEND)
        desc->no_suspend_depth--;
    else if (action->flags & IRQF_COND_SUSPEND)
        desc->cond_suspend_depth--;
}
