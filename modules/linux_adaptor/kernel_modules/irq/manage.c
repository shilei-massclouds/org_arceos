#include <linux/irq.h>

#include "internals.h"
#include "../adaptor.h"

cpumask_var_t irq_default_affinity;

void enable_percpu_irq(unsigned int irq, unsigned int type)
{
    pr_err("%s: No impl. irq(%u) type(%u)\n", __func__, irq, type);
}

static int __irq_set_affinity(unsigned int irq, const struct cpumask *mask,
                  bool force)
{
    struct irq_desc *desc = irq_to_desc(irq);
    unsigned long flags;
    int ret;

    if (!desc)
        return -EINVAL;

    raw_spin_lock_irqsave(&desc->lock, flags);
    ret = irq_set_affinity_locked(irq_desc_get_irq_data(desc), mask, force);
    raw_spin_unlock_irqrestore(&desc->lock, flags);
    return ret;
}

/**
 * irq_set_affinity - Set the irq affinity of a given irq
 * @irq:    Interrupt to set affinity
 * @cpumask:    cpumask
 *
 * Fails if cpumask does not contain an online CPU
 */
int irq_set_affinity(unsigned int irq, const struct cpumask *cpumask)
{
    return __irq_set_affinity(irq, cpumask, false);
}

static bool irq_set_affinity_deactivated(struct irq_data *data,
                     const struct cpumask *mask)
{
    struct irq_desc *desc = irq_data_to_desc(data);

    /*
     * Handle irq chips which can handle affinity only in activated
     * state correctly
     *
     * If the interrupt is not yet activated, just store the affinity
     * mask and do not call the chip driver at all. On activation the
     * driver has to make sure anyway that the interrupt is in a
     * usable state so startup works.
     */
    if (!IS_ENABLED(CONFIG_IRQ_DOMAIN_HIERARCHY) ||
        irqd_is_activated(data) || !irqd_affinity_on_activate(data))
        return false;

    cpumask_copy(desc->irq_common_data.affinity, mask);
    irq_data_update_effective_affinity(data, mask);
    irqd_set(data, IRQD_AFFINITY_SET);
    return true;
}

int irq_set_affinity_locked(struct irq_data *data, const struct cpumask *mask,
                bool force)
{
    struct irq_chip *chip = irq_data_get_irq_chip(data);
    struct irq_desc *desc = irq_data_to_desc(data);
    int ret = 0;

    if (!chip || !chip->irq_set_affinity)
        return -EINVAL;

    if (irq_set_affinity_deactivated(data, mask))
        return 0;

    pr_err("%s: No impl.", __func__);
#if 0
    if (irq_can_move_pcntxt(data) && !irqd_is_setaffinity_pending(data)) {
        ret = irq_try_set_affinity(data, mask, force);
    } else {
        irqd_set_move_pending(data);
        irq_copy_pending(desc, mask);
    }

    if (desc->affinity_notify) {
        kref_get(&desc->affinity_notify->kref);
        if (!schedule_work(&desc->affinity_notify->work)) {
            /* Work was already scheduled, drop our extra ref */
            kref_put(&desc->affinity_notify->kref,
                 desc->affinity_notify->release);
        }
    }
#endif
    irqd_set(data, IRQD_AFFINITY_SET);

    return ret;
}
