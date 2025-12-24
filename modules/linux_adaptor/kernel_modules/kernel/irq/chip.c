// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the core interrupt handling code, for irq-chip based
 * architectures. Detailed information is available in
 * Documentation/core-api/genericirq.rst
 */

#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/irqdomain.h>

#include <trace/events/irq.h>

#include "internals.h"
#include "adaptor.h"

static irqreturn_t bad_chained_irq(int irq, void *dev_id)
{
    WARN_ONCE(1, "Chained irq %d should not call an action\n", irq);
    return IRQ_NONE;
}

/*
 * Chained handlers should never call action on their IRQ. This default
 * action will emit warning if such thing happens.
 */
struct irqaction chained_action = {
    .handler = bad_chained_irq,
};

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

static void irq_state_clr_started(struct irq_desc *desc)
{
    irqd_clear(&desc->irq_data, IRQD_IRQ_STARTED);
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

static void __irq_disable(struct irq_desc *desc, bool mask)
{
    if (irqd_irq_disabled(&desc->irq_data)) {
        if (mask)
            mask_irq(desc);
    } else {
        irq_state_set_disabled(desc);
        if (desc->irq_data.chip->irq_disable) {
            desc->irq_data.chip->irq_disable(&desc->irq_data);
            irq_state_set_masked(desc);
        } else if (mask) {
            mask_irq(desc);
        }
    }
}

struct irq_data *irq_get_irq_data(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);

    return desc ? &desc->irq_data : NULL;
}

int irq_activate_and_startup(struct irq_desc *desc, bool resend)
{
    if (WARN_ON(irq_activate(desc)))
        return 0;
    return irq_startup(desc, resend, IRQ_START_FORCE);
}

void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set)
{
    unsigned long flags, trigger, tmp;
    struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

    if (!desc)
        return;

    /*
     * Warn when a driver sets the no autoenable flag on an already
     * active interrupt.
     */
    WARN_ON_ONCE(!desc->depth && (set & _IRQ_NOAUTOEN));

    irq_settings_clr_and_set(desc, clr, set);

    trigger = irqd_get_trigger_type(&desc->irq_data);

    irqd_clear(&desc->irq_data, IRQD_NO_BALANCING | IRQD_PER_CPU |
           IRQD_TRIGGER_MASK | IRQD_LEVEL | IRQD_MOVE_PCNTXT);
    if (irq_settings_has_no_balance_set(desc))
        irqd_set(&desc->irq_data, IRQD_NO_BALANCING);
    if (irq_settings_is_per_cpu(desc))
        irqd_set(&desc->irq_data, IRQD_PER_CPU);
    if (irq_settings_can_move_pcntxt(desc))
        irqd_set(&desc->irq_data, IRQD_MOVE_PCNTXT);
    if (irq_settings_is_level(desc))
        irqd_set(&desc->irq_data, IRQD_LEVEL);

    tmp = irq_settings_get_trigger_mask(desc);
    if (tmp != IRQ_TYPE_NONE)
        trigger = tmp;

    irqd_set(&desc->irq_data, trigger);

    irq_put_desc_unlock(desc, flags);
}

static inline void mask_ack_irq(struct irq_desc *desc)
{
    if (desc->irq_data.chip->irq_mask_ack) {
        desc->irq_data.chip->irq_mask_ack(&desc->irq_data);
        irq_state_set_masked(desc);
    } else {
        mask_irq(desc);
        if (desc->irq_data.chip->irq_ack)
            desc->irq_data.chip->irq_ack(&desc->irq_data);
    }
}

static void
__irq_do_set_handler(struct irq_desc *desc, irq_flow_handler_t handle,
             int is_chained, const char *name)
{
    if (!handle) {
        handle = handle_bad_irq;
    } else {
        struct irq_data *irq_data = &desc->irq_data;
#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
        /*
         * With hierarchical domains we might run into a
         * situation where the outermost chip is not yet set
         * up, but the inner chips are there.  Instead of
         * bailing we install the handler, but obviously we
         * cannot enable/startup the interrupt at this point.
         */
        while (irq_data) {
            if (irq_data->chip != &no_irq_chip)
                break;
            /*
             * Bail out if the outer chip is not set up
             * and the interrupt supposed to be started
             * right away.
             */
            if (WARN_ON(is_chained))
                return;
            /* Try the parent */
            irq_data = irq_data->parent_data;
        }
#endif
        if (WARN_ON(!irq_data || irq_data->chip == &no_irq_chip))
            return;
    }

    /* Uninstall? */
    if (handle == handle_bad_irq) {
        if (desc->irq_data.chip != &no_irq_chip)
            mask_ack_irq(desc);
        irq_state_set_disabled(desc);
        if (is_chained) {
            desc->action = NULL;
            WARN_ON(irq_chip_pm_put(irq_desc_get_irq_data(desc)));
        }
        desc->depth = 1;
    }
    desc->handle_irq = handle;
    desc->name = name;

    if (handle != handle_bad_irq && is_chained) {
        unsigned int type = irqd_get_trigger_type(&desc->irq_data);

        /*
         * We're about to start this interrupt immediately,
         * hence the need to set the trigger configuration.
         * But the .set_type callback may have overridden the
         * flow handler, ignoring that we're dealing with a
         * chained interrupt. Reset it immediately because we
         * do know better.
         */
        if (type != IRQ_TYPE_NONE) {
            __irq_set_trigger(desc, type);
            desc->handle_irq = handle;
        }

        irq_settings_set_noprobe(desc);
        irq_settings_set_norequest(desc);
        irq_settings_set_nothread(desc);
        desc->action = &chained_action;
        WARN_ON(irq_chip_pm_get(irq_desc_get_irq_data(desc)));
        irq_activate_and_startup(desc, IRQ_RESEND);
    }
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
    pr_notice("%s: No impl.\n", __func__);
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
    pr_notice("%s: No impl.\n", __func__);
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

static void cond_unmask_eoi_irq(struct irq_desc *desc, struct irq_chip *chip)
{
    if (!(desc->istate & IRQS_ONESHOT)) {
        chip->irq_eoi(&desc->irq_data);
        return;
    }
    /*
     * We need to unmask in the following cases:
     * - Oneshot irq which did not wake the thread (caused by a
     *   spurious interrupt or a primary handler handling it
     *   completely).
     */
    if (!irqd_irq_disabled(&desc->irq_data) &&
        irqd_irq_masked(&desc->irq_data) && !desc->threads_oneshot) {
        chip->irq_eoi(&desc->irq_data);
        unmask_irq(desc);
    } else if (!(chip->flags & IRQCHIP_EOI_THREADED)) {
        chip->irq_eoi(&desc->irq_data);
    }
}

static bool irq_check_poll(struct irq_desc *desc)
{
    if (!(desc->istate & IRQS_POLL_INPROGRESS))
        return false;
    return irq_wait_for_poll(desc);
}

static bool irq_may_run(struct irq_desc *desc)
{
    unsigned int mask = IRQD_IRQ_INPROGRESS | IRQD_WAKEUP_ARMED;

    /*
     * If the interrupt is not in progress and is not an armed
     * wakeup interrupt, proceed.
     */
    if (!irqd_has_set(&desc->irq_data, mask))
        return true;

    pr_notice("%s: No impl for irq_pm_check_wakeup.", __func__);
#if 0
    /*
     * If the interrupt is an armed wakeup source, mark it pending
     * and suspended, disable it and notify the pm core about the
     * event.
     */
    if (irq_pm_check_wakeup(desc))
        return false;
#endif

    /*
     * Handle a potential concurrent poll on a different core.
     */
    return irq_check_poll(desc);
}

/**
 *  handle_fasteoi_irq - irq handler for transparent controllers
 *  @desc:  the interrupt description structure for this irq
 *
 *  Only a single callback will be issued to the chip: an ->eoi()
 *  call when the interrupt has been serviced. This enables support
 *  for modern forms of interrupt handlers, which handle the flow
 *  details in hardware, transparently.
 */
void handle_fasteoi_irq(struct irq_desc *desc)
{
    struct irq_chip *chip = desc->irq_data.chip;

    raw_spin_lock(&desc->lock);

    /*
     * When an affinity change races with IRQ handling, the next interrupt
     * can arrive on the new CPU before the original CPU has completed
     * handling the previous one - it may need to be resent.
     */
    if (!irq_may_run(desc)) {
        if (irqd_needs_resend_when_in_progress(&desc->irq_data))
            desc->istate |= IRQS_PENDING;
        goto out;
    }

    desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

    /*
     * If its disabled or no action available
     * then mask it and get out of here:
     */
    if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
        desc->istate |= IRQS_PENDING;
        mask_irq(desc);
        goto out;
    }

    //kstat_incr_irqs_this_cpu(desc);
    if (desc->istate & IRQS_ONESHOT)
        mask_irq(desc);

    handle_irq_event(desc);

    cond_unmask_eoi_irq(desc, chip);

    /*
     * When the race described above happens this will resend the interrupt.
     */
    if (unlikely(desc->istate & IRQS_PENDING))
        check_irq_resend(desc, false);

    raw_spin_unlock(&desc->lock);
    return;
out:
    if (!(chip->flags & IRQCHIP_EOI_IF_HANDLED))
        chip->irq_eoi(&desc->irq_data);
    raw_spin_unlock(&desc->lock);
}

void irq_shutdown(struct irq_desc *desc)
{
    if (irqd_is_started(&desc->irq_data)) {
        clear_irq_resend(desc);
        desc->depth = 1;
        if (desc->irq_data.chip->irq_shutdown) {
            desc->irq_data.chip->irq_shutdown(&desc->irq_data);
            irq_state_set_disabled(desc);
            irq_state_set_masked(desc);
        } else {
            __irq_disable(desc, true);
        }
        irq_state_clr_started(desc);
    }
}

/**
 * irq_disable - Mark interrupt disabled
 * @desc:   irq descriptor which should be disabled
 *
 * If the chip does not implement the irq_disable callback, we
 * use a lazy disable approach. That means we mark the interrupt
 * disabled, but leave the hardware unmasked. That's an
 * optimization because we avoid the hardware access for the
 * common case where no interrupt happens after we marked it
 * disabled. If an interrupt happens, then the interrupt flow
 * handler masks the line at the hardware level and marks it
 * pending.
 *
 * If the interrupt chip does not implement the irq_disable callback,
 * a driver can disable the lazy approach for a particular irq line by
 * calling 'irq_set_status_flags(irq, IRQ_DISABLE_UNLAZY)'. This can
 * be used for devices which cannot disable the interrupt at the
 * device level under certain circumstances and have to use
 * disable_irq[_nosync] instead.
 */
void irq_disable(struct irq_desc *desc)
{
    __irq_disable(desc, irq_settings_disable_unlazy(desc));
}

/**
 * irq_chip_compose_msi_msg - Compose msi message for a irq chip
 * @data:   Pointer to interrupt specific data
 * @msg:    Pointer to the MSI message
 *
 * For hierarchical domains we find the first chip in the hierarchy
 * which implements the irq_compose_msi_msg callback. For non
 * hierarchical we use the top level chip.
 */
int irq_chip_compose_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
    struct irq_data *pos;

    for (pos = NULL; !pos && data; data = irqd_get_parent_data(data)) {
        if (data->chip && data->chip->irq_compose_msi_msg)
            pos = data;
    }

    if (!pos)
        return -ENOSYS;

    pos->chip->irq_compose_msi_msg(pos, msg);
    return 0;
}

void
irq_set_chained_handler_and_data(unsigned int irq, irq_flow_handler_t handle,
                 void *data)
{
    unsigned long flags;
    struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, 0);

    if (!desc)
        return;

    desc->irq_common_data.handler_data = data;
    __irq_do_set_handler(desc, handle, 1, NULL);

    irq_put_desc_busunlock(desc, flags);
}

/**
 *  irq_set_msi_desc_off - set MSI descriptor data for an irq at offset
 *  @irq_base:  Interrupt number base
 *  @irq_offset:    Interrupt number offset
 *  @entry:     Pointer to MSI descriptor data
 *
 *  Set the MSI descriptor entry for an irq at offset
 */
int irq_set_msi_desc_off(unsigned int irq_base, unsigned int irq_offset,
             struct msi_desc *entry)
{
    unsigned long flags;
    struct irq_desc *desc = irq_get_desc_lock(irq_base + irq_offset, &flags, IRQ_GET_DESC_CHECK_GLOBAL);

    if (!desc)
        return -EINVAL;
    desc->irq_common_data.msi_desc = entry;
    if (entry && !irq_offset)
        entry->irq = irq_base;
    irq_put_desc_unlock(desc, flags);
    return 0;
}

/**
 * irq_chip_unmask_parent - Unmask the parent interrupt
 * @data:   Pointer to interrupt specific data
 */
void irq_chip_unmask_parent(struct irq_data *data)
{
    data = data->parent_data;
    data->chip->irq_unmask(data);
}

/**
 *  handle_edge_irq - edge type IRQ handler
 *  @desc:  the interrupt description structure for this irq
 *
 *  Interrupt occurs on the falling and/or rising edge of a hardware
 *  signal. The occurrence is latched into the irq controller hardware
 *  and must be acked in order to be reenabled. After the ack another
 *  interrupt can happen on the same source even before the first one
 *  is handled by the associated event handler. If this happens it
 *  might be necessary to disable (mask) the interrupt depending on the
 *  controller hardware. This requires to reenable the interrupt inside
 *  of the loop which handles the interrupts which have arrived while
 *  the handler was running. If all pending interrupts are handled, the
 *  loop is left.
 */
void handle_edge_irq(struct irq_desc *desc)
{
    raw_spin_lock(&desc->lock);

    desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

    if (!irq_may_run(desc)) {
        desc->istate |= IRQS_PENDING;
        mask_ack_irq(desc);
        goto out_unlock;
    }

    /*
     * If its disabled or no action available then mask it and get
     * out of here.
     */
    if (irqd_irq_disabled(&desc->irq_data) || !desc->action) {
        desc->istate |= IRQS_PENDING;
        mask_ack_irq(desc);
        goto out_unlock;
    }

#if 0
    kstat_incr_irqs_this_cpu(desc);
#endif

    /* Start handling the irq */
    desc->irq_data.chip->irq_ack(&desc->irq_data);

    do {
        if (unlikely(!desc->action)) {
            mask_irq(desc);
            goto out_unlock;
        }

        /*
         * When another irq arrived while we were handling
         * one, we could have masked the irq.
         * Reenable it, if it was not disabled in meantime.
         */
        if (unlikely(desc->istate & IRQS_PENDING)) {
            if (!irqd_irq_disabled(&desc->irq_data) &&
                irqd_irq_masked(&desc->irq_data))
                unmask_irq(desc);
        }

        handle_irq_event(desc);

    } while ((desc->istate & IRQS_PENDING) &&
         !irqd_irq_disabled(&desc->irq_data));

out_unlock:
    raw_spin_unlock(&desc->lock);
}

/**
 * irq_chip_ack_parent - Acknowledge the parent interrupt
 * @data:   Pointer to interrupt specific data
 */
void irq_chip_ack_parent(struct irq_data *data)
{
    data = data->parent_data;
    data->chip->irq_ack(data);
}

/**
 * irq_chip_mask_parent - Mask the parent interrupt
 * @data:   Pointer to interrupt specific data
 */
void irq_chip_mask_parent(struct irq_data *data)
{
    data = data->parent_data;
    data->chip->irq_mask(data);
}

void
irq_set_chip_and_handler_name(unsigned int irq, const struct irq_chip *chip,
                  irq_flow_handler_t handle, const char *name)
{
    irq_set_chip(irq, chip);
    __irq_set_handler(irq, handle, 0, name);
}

/**
 *  irq_set_chip - set the irq chip for an irq
 *  @irq:   irq number
 *  @chip:  pointer to irq chip description structure
 */
int irq_set_chip(unsigned int irq, const struct irq_chip *chip)
{
    unsigned long flags;
    struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

    if (!desc)
        return -EINVAL;

    desc->irq_data.chip = (struct irq_chip *)(chip ?: &no_irq_chip);
    irq_put_desc_unlock(desc, flags);
    /*
     * For !CONFIG_SPARSE_IRQ make the irq show up in
     * allocated_irqs.
     */
    irq_mark_irq(irq);
    return 0;
}

void irq_percpu_enable(struct irq_desc *desc, unsigned int cpu)
{
    printk("%s: irqchip(%s) cpu[%u] chip[%s]\n",
           __func__, desc->irq_data.chip->name, cpu, desc->irq_data.chip->name);
    if (desc->irq_data.chip->irq_enable)
        desc->irq_data.chip->irq_enable(&desc->irq_data);
    else
        desc->irq_data.chip->irq_unmask(&desc->irq_data);
    cpumask_set_cpu(cpu, desc->percpu_enabled);
}

/**
 * irq_chip_set_affinity_parent - Set affinity on the parent interrupt
 * @data:   Pointer to interrupt specific data
 * @dest:   The affinity mask to set
 * @force:  Flag to enforce setting (disable online checks)
 *
 * Conditional, as the underlying parent chip might not implement it.
 */
int irq_chip_set_affinity_parent(struct irq_data *data,
                 const struct cpumask *dest, bool force)
{
    data = data->parent_data;
    if (data->chip->irq_set_affinity)
        return data->chip->irq_set_affinity(data, dest, force);

    return -ENOSYS;
}
