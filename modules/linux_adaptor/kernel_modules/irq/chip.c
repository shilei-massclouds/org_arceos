#include <linux/irq.h>
#include <linux/irqdomain.h>

#include "internals.h"
#include "../adaptor.h"

enum {
    IRQ_STARTUP_NORMAL,
    IRQ_STARTUP_MANAGED,
    IRQ_STARTUP_ABORT,
};

static void irq_state_clr_disabled(struct irq_desc *desc)
{
    irqd_clear(&desc->irq_data, IRQD_IRQ_DISABLED);
}

static void irq_state_clr_masked(struct irq_desc *desc)
{
    irqd_clear(&desc->irq_data, IRQD_IRQ_MASKED);
}

static void irq_state_set_started(struct irq_desc *desc)
{
    irqd_set(&desc->irq_data, IRQD_IRQ_STARTED);
}

#ifdef CONFIG_SMP
static int
__irq_startup_managed(struct irq_desc *desc, const struct cpumask *aff,
              bool force)
{
    struct irq_data *d = irq_desc_get_irq_data(desc);

    if (!irqd_affinity_is_managed(d))
        return IRQ_STARTUP_NORMAL;

    PANIC("");
}
#endif

static int __irq_startup(struct irq_desc *desc)
{
    struct irq_data *d = irq_desc_get_irq_data(desc);
    int ret = 0;

    /* Warn if this interrupt is not activated but try nevertheless */
    WARN_ON_ONCE(!irqd_is_activated(d));

    if (d->chip->irq_startup) {
        ret = d->chip->irq_startup(d);
        irq_state_clr_disabled(desc);
        irq_state_clr_masked(desc);
    } else {
        irq_enable(desc);
    }
    irq_state_set_started(desc);
    return ret;
}

struct irq_data *irq_get_irq_data(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);

    return desc ? &desc->irq_data : NULL;
}

void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set)
{
    pr_err("%s: No impl.\n", __func__);
}

static void
__irq_do_set_handler(struct irq_desc *desc, irq_flow_handler_t handle,
             int is_chained, const char *name)
{
    pr_err("%s: No impl.\n", __func__);
    if (!handle) {
        PANIC("No handle.");
    }
    if (!desc) {
        PANIC("No desc.");
    }

    desc->handle_irq = handle;
    desc->name = name;
}

void
__irq_set_handler(unsigned int irq, irq_flow_handler_t handle, int is_chained,
          const char *name)
{
    unsigned long flags;
    struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, 0);

    if (!desc)
        return;

    __irq_do_set_handler(desc, handle, is_chained, name);
    irq_put_desc_busunlock(desc, flags);
}

/**
 *  irq_set_handler_data - set irq handler data for an irq
 *  @irq:   Interrupt number
 *  @data:  Pointer to interrupt specific data
 *
 *  Set the hardware irq controller data for an irq
 */
int irq_set_handler_data(unsigned int irq, void *data)
{
    unsigned long flags;
    struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

    if (!desc)
        return -EINVAL;
    desc->irq_common_data.handler_data = data;
    irq_put_desc_unlock(desc, flags);
    return 0;
}

/**
 * irq_chip_pm_get - Enable power for an IRQ chip
 * @data:   Pointer to interrupt specific data
 *
 * Enable the power to the IRQ chip referenced by the interrupt data
 * structure.
 */
int irq_chip_pm_get(struct irq_data *data)
{
    pr_err("%s: No impl.\n", __func__);
    return 0;
#if 0
    struct device *dev = irq_get_pm_device(data);
    int retval = 0;

    if (IS_ENABLED(CONFIG_PM) && dev)
        retval = pm_runtime_resume_and_get(dev);

    return retval;
#endif
}


/**
 * irq_chip_pm_put - Disable power for an IRQ chip
 * @data:   Pointer to interrupt specific data
 *
 * Disable the power to the IRQ chip referenced by the interrupt data
 * structure, belongs. Note that power will only be disabled, once this
 * function has been called for all IRQs that have called irq_chip_pm_get().
 */
int irq_chip_pm_put(struct irq_data *data)
{
    pr_err("%s: No impl.\n", __func__);
    return 0;
#if 0
    struct device *dev = irq_get_pm_device(data);
    int retval = 0;

    if (IS_ENABLED(CONFIG_PM) && dev)
        retval = pm_runtime_put(dev);

    return (retval < 0) ? retval : 0;
#endif
}

int irq_activate(struct irq_desc *desc)
{
    struct irq_data *d = irq_desc_get_irq_data(desc);

    if (!irqd_affinity_is_managed(d))
        return irq_domain_activate_irq(d, false);
    return 0;
}

int irq_startup(struct irq_desc *desc, bool resend, bool force)
{
    struct irq_data *d = irq_desc_get_irq_data(desc);
    const struct cpumask *aff = irq_data_get_affinity_mask(d);
    int ret = 0;

    desc->depth = 0;

    if (irqd_is_started(d)) {
        irq_enable(desc);
    } else {
        switch (__irq_startup_managed(desc, aff, force)) {
        case IRQ_STARTUP_NORMAL:
            if (d->chip->flags & IRQCHIP_AFFINITY_PRE_STARTUP)
                irq_setup_affinity(desc);
            ret = __irq_startup(desc);
            if (!(d->chip->flags & IRQCHIP_AFFINITY_PRE_STARTUP))
                irq_setup_affinity(desc);
            break;
        case IRQ_STARTUP_MANAGED:
            irq_do_set_affinity(d, aff, false);
            ret = __irq_startup(desc);
            break;
        case IRQ_STARTUP_ABORT:
            irqd_set_managed_shutdown(d);
            return 0;
        }
    }
    if (resend)
        check_irq_resend(desc, false);

    return ret;
}

#ifndef CONFIG_AUTO_IRQ_AFFINITY
/*
 * Generic version of the affinity autoselector.
 */
int irq_setup_affinity(struct irq_desc *desc)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}
#endif

void irq_enable(struct irq_desc *desc)
{
    if (!irqd_irq_disabled(&desc->irq_data)) {
        unmask_irq(desc);
    } else {
        irq_state_clr_disabled(desc);
        if (desc->irq_data.chip->irq_enable) {
            desc->irq_data.chip->irq_enable(&desc->irq_data);
            irq_state_clr_masked(desc);
        } else {
            unmask_irq(desc);
        }
    }
}

void mask_irq(struct irq_desc *desc)
{
    if (irqd_irq_masked(&desc->irq_data))
        return;

    if (desc->irq_data.chip->irq_mask) {
        desc->irq_data.chip->irq_mask(&desc->irq_data);
        irq_state_set_masked(desc);
    }
}

void unmask_irq(struct irq_desc *desc)
{
    if (!irqd_irq_masked(&desc->irq_data))
        return;

    if (desc->irq_data.chip->irq_unmask) {
        desc->irq_data.chip->irq_unmask(&desc->irq_data);
        irq_state_clr_masked(desc);
    }
}
