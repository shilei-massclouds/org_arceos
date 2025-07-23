#include <linux/irq.h>
#include <linux/kthread.h>

#include "internals.h"
#include "../adaptor.h"

cpumask_var_t irq_default_affinity;

/*
 * Primary handler for nested threaded interrupts. Should never be
 * called.
 */
static irqreturn_t irq_nested_primary_handler(int irq, void *dev_id)
{
    WARN(1, "Primary handler called for nested irq %d\n", irq);
    return IRQ_NONE;
}

/*
 * Default primary interrupt handler for threaded interrupts. Is
 * assigned as primary handler when request_threaded_irq is called
 * with handler == NULL. Useful for oneshot interrupts.
 */
static irqreturn_t irq_default_primary_handler(int irq, void *dev_id)
{
    return IRQ_WAKE_THREAD;
}

static int irq_setup_forced_threading(struct irqaction *new)
{
    if (!force_irqthreads())
        return 0;
    if (new->flags & (IRQF_NO_THREAD | IRQF_PERCPU | IRQF_ONESHOT))
        return 0;

    /*
     * No further action required for interrupts which are requested as
     * threaded interrupts already
     */
    if (new->handler == irq_default_primary_handler)
        return 0;

    PANIC("");
}

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

static int irq_request_resources(struct irq_desc *desc)
{
    struct irq_data *d = &desc->irq_data;
    struct irq_chip *c = d->chip;

    return c->irq_request_resources ? c->irq_request_resources(d) : 0;
}

static void irq_release_resources(struct irq_desc *desc)
{
    struct irq_data *d = &desc->irq_data;
    struct irq_chip *c = d->chip;

    if (c->irq_release_resources)
        c->irq_release_resources(d);
}

int __irq_set_trigger(struct irq_desc *desc, unsigned long flags)
{
    struct irq_chip *chip = desc->irq_data.chip;
    int ret, unmask = 0;

    if (!chip || !chip->irq_set_type) {
        /*
         * IRQF_TRIGGER_* but the PIC does not support multiple
         * flow-types?
         */
        pr_debug("No set_type function for IRQ %d (%s)\n",
             irq_desc_get_irq(desc),
             chip ? (chip->name ? : "unknown") : "unknown");
        return 0;
    }

    PANIC("");
}

/*
 * Internal function to wake up a interrupt thread and wait until it is
 * ready.
 */
static void wake_up_and_wait_for_irq_thread_ready(struct irq_desc *desc,
                          struct irqaction *action)
{
    if (!action || !action->thread)
        return;

#if 0
    wake_up_process(action->thread);
    wait_event(desc->wait_for_threads,
           test_bit(IRQTF_READY, &action->thread_flags));
#endif
    PANIC("");
}

/*
 * Internal function to register an irqaction - typically used to
 * allocate special interrupts that are part of the architecture.
 *
 * Locking rules:
 *
 * desc->request_mutex  Provides serialization against a concurrent free_irq()
 *   chip_bus_lock  Provides serialization for slow bus operations
 *     desc->lock   Provides serialization against hard interrupts
 *
 * chip_bus_lock and desc->lock are sufficient for all other management and
 * interrupt related functions. desc->request_mutex solely serializes
 * request/free_irq().
 */
static int
__setup_irq(unsigned int irq, struct irq_desc *desc, struct irqaction *new)
{
    struct irqaction *old, **old_ptr;
    unsigned long flags, thread_mask = 0;
    int ret, nested, shared = 0;

    if (!desc)
        return -EINVAL;

    if (desc->irq_data.chip == &no_irq_chip)
        return -ENOSYS;
    if (!try_module_get(desc->owner))
        return -ENODEV;

    new->irq = irq;

    /*
     * If the trigger type is not specified by the caller,
     * then use the default for this interrupt.
     */
    if (!(new->flags & IRQF_TRIGGER_MASK))
        new->flags |= irqd_get_trigger_type(&desc->irq_data);

    /*
     * Check whether the interrupt nests into another interrupt
     * thread.
     */
    nested = irq_settings_is_nested_thread(desc);
    if (nested) {
        if (!new->thread_fn) {
            ret = -EINVAL;
            goto out_mput;
        }
        /*
         * Replace the primary handler which was provided from
         * the driver for non nested interrupt handling by the
         * dummy function which warns when called.
         */
        new->handler = irq_nested_primary_handler;
    } else {
        if (irq_settings_can_thread(desc)) {
            ret = irq_setup_forced_threading(new);
            if (ret)
                goto out_mput;
        }
    }

    /*
     * Create a handler thread when a thread function is supplied
     * and the interrupt does not nest into another interrupt
     * thread.
     */
    if (new->thread_fn && !nested) {
        PANIC("it has thread_fn.");
#if 0
        ret = setup_irq_thread(new, irq, false);
        if (ret)
            goto out_mput;
        if (new->secondary) {
            ret = setup_irq_thread(new->secondary, irq, true);
            if (ret)
                goto out_thread;
        }
#endif
    }

    /*
     * Drivers are often written to work w/o knowledge about the
     * underlying irq chip implementation, so a request for a
     * threaded irq without a primary hard irq context handler
     * requires the ONESHOT flag to be set. Some irq chips like
     * MSI based interrupts are per se one shot safe. Check the
     * chip flags, so we can avoid the unmask dance at the end of
     * the threaded handler for those.
     */
    if (desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)
        new->flags &= ~IRQF_ONESHOT;

    /*
     * Protects against a concurrent __free_irq() call which might wait
     * for synchronize_hardirq() to complete without holding the optional
     * chip bus lock and desc->lock. Also protects against handing out
     * a recycled oneshot thread_mask bit while it's still in use by
     * its previous owner.
     */
    mutex_lock(&desc->request_mutex);

    /*
     * Acquire bus lock as the irq_request_resources() callback below
     * might rely on the serialization or the magic power management
     * functions which are abusing the irq_bus_lock() callback,
     */
    chip_bus_lock(desc);

    /* First installed action requests resources. */
    if (!desc->action) {
        ret = irq_request_resources(desc);
        if (ret) {
            pr_err("Failed to request resources for %s (irq %d) on irqchip %s\n",
                   new->name, irq, desc->irq_data.chip->name);
            goto out_bus_unlock;
        }
    }

    /*
     * The following block of code has to be executed atomically
     * protected against a concurrent interrupt and any of the other
     * management calls which are not serialized via
     * desc->request_mutex or the optional bus lock.
     */
    raw_spin_lock_irqsave(&desc->lock, flags);
    old_ptr = &desc->action;
    old = *old_ptr;
    if (old) {
        PANIC("it has old.");
    }


    /*
     * Setup the thread mask for this irqaction for ONESHOT. For
     * !ONESHOT irqs the thread mask is 0 so we can avoid a
     * conditional in irq_wake_thread().
     */
    if (new->flags & IRQF_ONESHOT) {
        PANIC("flags with IRQF_ONESHOT.");
    } else if (new->handler == irq_default_primary_handler &&
           !(desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)) {
        /*
         * The interrupt was requested with handler = NULL, so
         * we use the default primary handler for it. But it
         * does not have the oneshot flag set. In combination
         * with level interrupts this is deadly, because the
         * default primary handler just wakes the thread, then
         * the irq lines is reenabled, but the device still
         * has the level irq asserted. Rinse and repeat....
         *
         * While this works for edge type interrupts, we play
         * it safe and reject unconditionally because we can't
         * say for sure which type this interrupt really
         * has. The type flags are unreliable as the
         * underlying chip implementation can override them.
         */
        pr_err("Threaded irq requested with handler=NULL and !ONESHOT for %s (irq %d)\n",
               new->name, irq);
        ret = -EINVAL;
        goto out_unlock;
    }

    if (!shared) {
        /* Setup the type (level, edge polarity) if configured: */
        if (new->flags & IRQF_TRIGGER_MASK) {
            ret = __irq_set_trigger(desc,
                        new->flags & IRQF_TRIGGER_MASK);

            if (ret)
                goto out_unlock;
        }

        /*
         * Activate the interrupt. That activation must happen
         * independently of IRQ_NOAUTOEN. request_irq() can fail
         * and the callers are supposed to handle
         * that. enable_irq() of an interrupt requested with
         * IRQ_NOAUTOEN is not supposed to fail. The activation
         * keeps it in shutdown mode, it merily associates
         * resources if necessary and if that's not possible it
         * fails. Interrupts which are in managed shutdown mode
         * will simply ignore that activation request.
         */
        ret = irq_activate(desc);
        if (ret)
            goto out_unlock;

        desc->istate &= ~(IRQS_AUTODETECT | IRQS_SPURIOUS_DISABLED | \
                  IRQS_ONESHOT | IRQS_WAITING);
        irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);

        if (new->flags & IRQF_PERCPU) {
            irqd_set(&desc->irq_data, IRQD_PER_CPU);
            irq_settings_set_per_cpu(desc);
            if (new->flags & IRQF_NO_DEBUG)
                irq_settings_set_no_debug(desc);
        }

        if (noirqdebug)
            irq_settings_set_no_debug(desc);

        if (new->flags & IRQF_ONESHOT)
            desc->istate |= IRQS_ONESHOT;

        /* Exclude IRQ from balancing if requested */
        if (new->flags & IRQF_NOBALANCING) {
            irq_settings_set_no_balancing(desc);
            irqd_set(&desc->irq_data, IRQD_NO_BALANCING);
        }

        if (!(new->flags & IRQF_NO_AUTOEN) &&
            irq_settings_can_autoenable(desc)) {
            irq_startup(desc, IRQ_RESEND, IRQ_START_COND);
        } else {
            /*
             * Shared interrupts do not go well with disabling
             * auto enable. The sharing interrupt might request
             * it while it's still disabled and then wait for
             * interrupts forever.
             */
            WARN_ON_ONCE(new->flags & IRQF_SHARED);
            /* Undo nested disables: */
            desc->depth = 1;
        }

    } else if (new->flags & IRQF_TRIGGER_MASK) {
        unsigned int nmsk = new->flags & IRQF_TRIGGER_MASK;
        unsigned int omsk = irqd_get_trigger_type(&desc->irq_data);

        if (nmsk != omsk)
            /* hope the handler works with current  trigger mode */
            pr_warn("irq %d uses trigger mode %u; requested %u\n",
                irq, omsk, nmsk);
    }

    *old_ptr = new;

    //irq_pm_install_action(desc, new);

    /* Reset broken irq detection when installing new handler */
    desc->irq_count = 0;
    desc->irqs_unhandled = 0;

    /*
     * Check whether we disabled the irq via the spurious handler
     * before. Reenable it and give it another chance.
     */
    if (shared && (desc->istate & IRQS_SPURIOUS_DISABLED)) {
        desc->istate &= ~IRQS_SPURIOUS_DISABLED;
        __enable_irq(desc);
    }

    raw_spin_unlock_irqrestore(&desc->lock, flags);
    chip_bus_sync_unlock(desc);
    mutex_unlock(&desc->request_mutex);

    irq_setup_timings(desc, new);

    wake_up_and_wait_for_irq_thread_ready(desc, new);
    wake_up_and_wait_for_irq_thread_ready(desc, new->secondary);

    //register_irq_proc(irq, desc);
    new->dir = NULL;
    //register_handler_proc(irq, new);
    return 0;

out_unlock:
    raw_spin_unlock_irqrestore(&desc->lock, flags);

    if (!desc->action)
        irq_release_resources(desc);
out_bus_unlock:
    chip_bus_sync_unlock(desc);
    mutex_unlock(&desc->request_mutex);

out_thread:
    if (new->thread) {
        struct task_struct *t = new->thread;

        new->thread = NULL;
        kthread_stop_put(t);
    }
    if (new->secondary && new->secondary->thread) {
        struct task_struct *t = new->secondary->thread;

        new->secondary->thread = NULL;
        kthread_stop_put(t);
    }
out_mput:
    module_put(desc->owner);
    return ret;
}

/**
 *  request_threaded_irq - allocate an interrupt line
 *  @irq: Interrupt line to allocate
 *  @handler: Function to be called when the IRQ occurs.
 *        Primary handler for threaded interrupts.
 *        If handler is NULL and thread_fn != NULL
 *        the default primary handler is installed.
 *  @thread_fn: Function called from the irq handler thread
 *          If NULL, no irq thread is created
 *  @irqflags: Interrupt type flags
 *  @devname: An ascii name for the claiming device
 *  @dev_id: A cookie passed back to the handler function
 *
 *  This call allocates interrupt resources and enables the
 *  interrupt line and IRQ handling. From the point this
 *  call is made your handler function may be invoked. Since
 *  your handler function must clear any interrupt the board
 *  raises, you must take care both to initialise your hardware
 *  and to set up the interrupt handler in the right order.
 *
 *  If you want to set up a threaded irq handler for your device
 *  then you need to supply @handler and @thread_fn. @handler is
 *  still called in hard interrupt context and has to check
 *  whether the interrupt originates from the device. If yes it
 *  needs to disable the interrupt on the device and return
 *  IRQ_WAKE_THREAD which will wake up the handler thread and run
 *  @thread_fn. This split handler design is necessary to support
 *  shared interrupts.
 *
 *  Dev_id must be globally unique. Normally the address of the
 *  device data structure is used as the cookie. Since the handler
 *  receives this value it makes sense to use it.
 *
 *  If your interrupt is shared you must pass a non NULL dev_id
 *  as this is required when freeing the interrupt.
 *
 *  Flags:
 *
 *  IRQF_SHARED     Interrupt is shared
 *  IRQF_TRIGGER_*      Specify active edge(s) or level
 *  IRQF_ONESHOT        Run thread_fn with interrupt line masked
 */
int request_threaded_irq(unsigned int irq, irq_handler_t handler,
             irq_handler_t thread_fn, unsigned long irqflags,
             const char *devname, void *dev_id)
{
    struct irqaction *action;
    struct irq_desc *desc;
    int retval;

    if (irq == IRQ_NOTCONNECTED)
        return -ENOTCONN;

    /*
     * Sanity-check: shared interrupts must pass in a real dev-ID,
     * otherwise we'll have trouble later trying to figure out
     * which interrupt is which (messes up the interrupt freeing
     * logic etc).
     *
     * Also shared interrupts do not go well with disabling auto enable.
     * The sharing interrupt might request it while it's still disabled
     * and then wait for interrupts forever.
     *
     * Also IRQF_COND_SUSPEND only makes sense for shared interrupts and
     * it cannot be set along with IRQF_NO_SUSPEND.
     */
    if (((irqflags & IRQF_SHARED) && !dev_id) ||
        ((irqflags & IRQF_SHARED) && (irqflags & IRQF_NO_AUTOEN)) ||
        (!(irqflags & IRQF_SHARED) && (irqflags & IRQF_COND_SUSPEND)) ||
        ((irqflags & IRQF_NO_SUSPEND) && (irqflags & IRQF_COND_SUSPEND)))
        return -EINVAL;

    desc = irq_to_desc(irq);
    if (!desc)
        return -EINVAL;

    if (!irq_settings_can_request(desc) ||
        WARN_ON(irq_settings_is_per_cpu_devid(desc)))
        return -EINVAL;

    if (!handler) {
        if (!thread_fn)
            return -EINVAL;
        handler = irq_default_primary_handler;
    }

    action = kzalloc(sizeof(struct irqaction), GFP_KERNEL);
    if (!action)
        return -ENOMEM;

    action->handler = handler;
    action->thread_fn = thread_fn;
    action->flags = irqflags;
    action->name = devname;
    action->dev_id = dev_id;

    retval = irq_chip_pm_get(&desc->irq_data);
    if (retval < 0) {
        kfree(action);
        return retval;
    }

    retval = __setup_irq(irq, desc, action);

    if (retval) {
        irq_chip_pm_put(&desc->irq_data);
        kfree(action->secondary);
        kfree(action);
    }

#ifdef CONFIG_DEBUG_SHIRQ_FIXME
    if (!retval && (irqflags & IRQF_SHARED)) {
        /*
         * It's a shared IRQ -- the driver ought to be prepared for it
         * to happen immediately, so let's make sure....
         * We disable the irq to make sure that a 'real' IRQ doesn't
         * run in parallel with our fake.
         */
        unsigned long flags;

        disable_irq(irq);
        local_irq_save(flags);

        handler(irq, dev_id);

        local_irq_restore(flags);
        enable_irq(irq);
    }
#endif
    return retval;
}
