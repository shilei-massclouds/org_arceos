#define pr_fmt(fmt) "genirq: " fmt

#include <linux/irq.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#include <linux/sched/isolation.h>
#include <uapi/linux/sched/types.h>
#include <linux/task_work.h>

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

static void irq_validate_effective_affinity(struct irq_data *data)
{
    const struct cpumask *m = irq_data_get_effective_affinity_mask(data);
    struct irq_chip *chip = irq_data_get_irq_chip(data);

    if (!cpumask_empty(m))
        return;
    pr_warn_once("irq_chip %s did not update eff. affinity mask of irq %u\n",
             chip->name, data->irq);
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
    pr_notice("%s: No impl. irq(%u) type(%u)\n", __func__, irq, type);
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

static inline int irq_set_affinity_pending(struct irq_data *data,
                       const struct cpumask *dest)
{
    return -EBUSY;
}

static int irq_try_set_affinity(struct irq_data *data,
                const struct cpumask *dest, bool force)
{
    int ret = irq_do_set_affinity(data, dest, force);

    /*
     * In case that the underlying vector management is busy and the
     * architecture supports the generic pending mechanism then utilize
     * this to avoid returning an error to user space.
     */
    if (ret == -EBUSY && !force)
        ret = irq_set_affinity_pending(data, dest);
    return ret;
}

static DEFINE_PER_CPU(struct cpumask, __tmp_mask);

int irq_do_set_affinity(struct irq_data *data, const struct cpumask *mask,
            bool force)
{
    struct cpumask *tmp_mask = this_cpu_ptr(&__tmp_mask);
    struct irq_desc *desc = irq_data_to_desc(data);
    struct irq_chip *chip = irq_data_get_irq_chip(data);
    const struct cpumask  *prog_mask;
    int ret;

    if (!chip || !chip->irq_set_affinity)
        return -EINVAL;

    /*
     * If this is a managed interrupt and housekeeping is enabled on
     * it check whether the requested affinity mask intersects with
     * a housekeeping CPU. If so, then remove the isolated CPUs from
     * the mask and just keep the housekeeping CPU(s). This prevents
     * the affinity setter from routing the interrupt to an isolated
     * CPU to avoid that I/O submitted from a housekeeping CPU causes
     * interrupts on an isolated one.
     *
     * If the masks do not intersect or include online CPU(s) then
     * keep the requested mask. The isolated target CPUs are only
     * receiving interrupts when the I/O operation was submitted
     * directly from them.
     *
     * If all housekeeping CPUs in the affinity mask are offline, the
     * interrupt will be migrated by the CPU hotplug code once a
     * housekeeping CPU which belongs to the affinity mask comes
     * online.
     */
    if (irqd_affinity_is_managed(data) &&
        housekeeping_enabled(HK_TYPE_MANAGED_IRQ)) {
        const struct cpumask *hk_mask;

        hk_mask = housekeeping_cpumask(HK_TYPE_MANAGED_IRQ);

        cpumask_and(tmp_mask, mask, hk_mask);
        if (!cpumask_intersects(tmp_mask, cpu_online_mask))
            prog_mask = mask;
        else
            prog_mask = tmp_mask;
    } else {
        prog_mask = mask;
    }

    /*
     * Make sure we only provide online CPUs to the irqchip,
     * unless we are being asked to force the affinity (in which
     * case we do as we are told).
     */
    cpumask_and(tmp_mask, prog_mask, cpu_online_mask);
    if (!force && !cpumask_empty(tmp_mask))
        ret = chip->irq_set_affinity(data, tmp_mask, force);
    else if (force)
        ret = chip->irq_set_affinity(data, mask, force);
    else
        ret = -EINVAL;

    switch (ret) {
    case IRQ_SET_MASK_OK:
    case IRQ_SET_MASK_OK_DONE:
        cpumask_copy(desc->irq_common_data.affinity, mask);
        fallthrough;
    case IRQ_SET_MASK_OK_NOCOPY:
        irq_validate_effective_affinity(data);
        irq_set_thread_affinity(desc);
        ret = 0;
    }

    return ret;
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

    if (irq_can_move_pcntxt(data) && !irqd_is_setaffinity_pending(data)) {
        ret = irq_try_set_affinity(data, mask, force);
    } else {
        irqd_set_move_pending(data);
        irq_copy_pending(desc, mask);
    }

    pr_notice("%s: No impl.", __func__);
#if 0
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
        /*
         * Can't share interrupts unless both agree to and are
         * the same type (level, edge, polarity). So both flag
         * fields must have IRQF_SHARED set and the bits which
         * set the trigger type must match. Also all must
         * agree on ONESHOT.
         * Interrupt lines used for NMIs cannot be shared.
         */
        unsigned int oldtype;

        if (irq_is_nmi(desc)) {
            pr_err("Invalid attempt to share NMI for %s (irq %d) on irqchip %s.\n",
                new->name, irq, desc->irq_data.chip->name);
            ret = -EINVAL;
            goto out_unlock;
        }

        /*
         * If nobody did set the configuration before, inherit
         * the one provided by the requester.
         */
        if (irqd_trigger_type_was_set(&desc->irq_data)) {
            oldtype = irqd_get_trigger_type(&desc->irq_data);
        } else {
            oldtype = new->flags & IRQF_TRIGGER_MASK;
            irqd_set_trigger_type(&desc->irq_data, oldtype);
        }

        if (!((old->flags & new->flags) & IRQF_SHARED) ||
            (oldtype != (new->flags & IRQF_TRIGGER_MASK)))
            goto mismatch;

        if ((old->flags & IRQF_ONESHOT) &&
            (new->flags & IRQF_COND_ONESHOT))
            new->flags |= IRQF_ONESHOT;
        else if ((old->flags ^ new->flags) & IRQF_ONESHOT)
            goto mismatch;

        /* All handlers must agree on per-cpuness */
        if ((old->flags & IRQF_PERCPU) !=
            (new->flags & IRQF_PERCPU))
            goto mismatch;

        /* add new interrupt at end of irq queue */
        do {
            /*
             * Or all existing action->thread_mask bits,
             * so we can find the next zero bit for this
             * new action.
             */
            thread_mask |= old->thread_mask;
            old_ptr = &old->next;
            old = *old_ptr;
        } while (old);
        shared = 1;
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

mismatch:
    if (!(new->flags & IRQF_PROBE_SHARED)) {
        pr_err("Flags mismatch irq %d. %08x (%s) vs. %08x (%s)\n",
               irq, new->flags, new->name, old->flags, old->name);
#ifdef CONFIG_DEBUG_SHIRQ
        dump_stack();
#endif
    }
    ret = -EBUSY;

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

void __enable_irq(struct irq_desc *desc)
{
    switch (desc->depth) {
    case 0:
 err_out:
        WARN(1, KERN_WARNING "Unbalanced enable for IRQ %d\n",
             irq_desc_get_irq(desc));
        break;
    case 1: {
        if (desc->istate & IRQS_SUSPENDED)
            goto err_out;
        /* Prevent probing on this irq: */
        irq_settings_set_noprobe(desc);
        /*
         * Call irq_startup() not irq_enable() here because the
         * interrupt might be marked NOAUTOEN so irq_startup()
         * needs to be invoked when it gets enabled the first time.
         * This is also required when __enable_irq() is invoked for
         * a managed and shutdown interrupt from the S3 resume
         * path.
         *
         * If it was already started up, then irq_startup() will
         * invoke irq_enable() under the hood.
         */
        irq_startup(desc, IRQ_RESEND, IRQ_START_FORCE);
        break;
    }
    default:
        desc->depth--;
    }
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

/**
 *  irq_set_thread_affinity - Notify irq threads to adjust affinity
 *  @desc:      irq descriptor which has affinity changed
 *
 *  We just set IRQTF_AFFINITY and delegate the affinity setting
 *  to the interrupt thread itself. We can not call
 *  set_cpus_allowed_ptr() here as we hold desc->lock and this
 *  code can be called from hard interrupt context.
 */
void irq_set_thread_affinity(struct irq_desc *desc)
{
    struct irqaction *action;

    for_each_action_of_desc(desc, action) {
        if (action->thread) {
            set_bit(IRQTF_AFFINITY, &action->thread_flags);
            wake_up_process(action->thread);
        }
        if (action->secondary && action->secondary->thread) {
            set_bit(IRQTF_AFFINITY, &action->secondary->thread_flags);
            wake_up_process(action->secondary->thread);
        }
    }
}

static void __synchronize_hardirq(struct irq_desc *desc, bool sync_chip)
{
    struct irq_data *irqd = irq_desc_get_irq_data(desc);
    bool inprogress;

    do {
        unsigned long flags;

        /*
         * Wait until we're out of the critical section.  This might
         * give the wrong answer due to the lack of memory barriers.
         */
        while (irqd_irq_inprogress(&desc->irq_data))
            cpu_relax();

        /* Ok, that indicated we're done: double-check carefully. */
        raw_spin_lock_irqsave(&desc->lock, flags);
        inprogress = irqd_irq_inprogress(&desc->irq_data);

        /*
         * If requested and supported, check at the chip whether it
         * is in flight at the hardware level, i.e. already pending
         * in a CPU and waiting for service and acknowledge.
         */
        if (!inprogress && sync_chip) {
            /*
             * Ignore the return code. inprogress is only updated
             * when the chip supports it.
             */
            __irq_get_irqchip_state(irqd, IRQCHIP_STATE_ACTIVE,
                        &inprogress);
        }
        raw_spin_unlock_irqrestore(&desc->lock, flags);

        /* Oops, that failed? */
    } while (inprogress);
}

int __irq_get_irqchip_state(struct irq_data *data, enum irqchip_irq_state which,
                bool *state)
{
    struct irq_chip *chip;
    int err = -EINVAL;

    do {
        chip = irq_data_get_irq_chip(data);
        if (WARN_ON_ONCE(!chip))
            return -ENODEV;
        if (chip->irq_get_irqchip_state)
            break;
#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
        data = data->parent_data;
#else
        data = NULL;
#endif
    } while (data);

    if (data)
        err = chip->irq_get_irqchip_state(data, which, state);
    return err;
}

static void __synchronize_irq(struct irq_desc *desc)
{
    __synchronize_hardirq(desc, true);
    /*
     * We made sure that no hardirq handler is running. Now verify that no
     * threaded handlers are active.
     */
    wait_event(desc->wait_for_threads, !atomic_read(&desc->threads_active));
}

/*
 * Internal function to unregister an irqaction - used to free
 * regular and special interrupts that are part of the architecture.
 */
static struct irqaction *__free_irq(struct irq_desc *desc, void *dev_id)
{
    unsigned irq = desc->irq_data.irq;
    struct irqaction *action, **action_ptr;
    unsigned long flags;

    WARN(in_interrupt(), "Trying to free IRQ %d from IRQ context!\n", irq);

    mutex_lock(&desc->request_mutex);
    chip_bus_lock(desc);
    raw_spin_lock_irqsave(&desc->lock, flags);

    /*
     * There can be multiple actions per IRQ descriptor, find the right
     * one based on the dev_id:
     */
    action_ptr = &desc->action;
    for (;;) {
        action = *action_ptr;

        if (!action) {
            WARN(1, "Trying to free already-free IRQ %d\n", irq);
            raw_spin_unlock_irqrestore(&desc->lock, flags);
            chip_bus_sync_unlock(desc);
            mutex_unlock(&desc->request_mutex);
            return NULL;
        }

        if (action->dev_id == dev_id)
            break;
        action_ptr = &action->next;
    }

    /* Found it - now remove it from the list of entries: */
    *action_ptr = action->next;

    irq_pm_remove_action(desc, action);

    /* If this was the last handler, shut down the IRQ line: */
    if (!desc->action) {
        irq_settings_clr_disable_unlazy(desc);
        /* Only shutdown. Deactivate after synchronize_hardirq() */
        irq_shutdown(desc);
    }

#ifdef CONFIG_SMP
    /* make sure affinity_hint is cleaned up */
    if (WARN_ON_ONCE(desc->affinity_hint))
        desc->affinity_hint = NULL;
#endif

    raw_spin_unlock_irqrestore(&desc->lock, flags);
    /*
     * Drop bus_lock here so the changes which were done in the chip
     * callbacks above are synced out to the irq chips which hang
     * behind a slow bus (I2C, SPI) before calling synchronize_hardirq().
     *
     * Aside of that the bus_lock can also be taken from the threaded
     * handler in irq_finalize_oneshot() which results in a deadlock
     * because kthread_stop() would wait forever for the thread to
     * complete, which is blocked on the bus lock.
     *
     * The still held desc->request_mutex() protects against a
     * concurrent request_irq() of this irq so the release of resources
     * and timing data is properly serialized.
     */
    chip_bus_sync_unlock(desc);

    unregister_handler_proc(irq, action);

    /*
     * Make sure it's not being used on another CPU and if the chip
     * supports it also make sure that there is no (not yet serviced)
     * interrupt in flight at the hardware level.
     */
    __synchronize_irq(desc);

#ifdef CONFIG_DEBUG_SHIRQ
    /*
     * It's a shared IRQ -- the driver ought to be prepared for an IRQ
     * event to happen even now it's being freed, so let's make sure that
     * is so by doing an extra call to the handler ....
     *
     * ( We do this after actually deregistering it, to make sure that a
     *   'real' IRQ doesn't run in parallel with our fake. )
     */
    if (action->flags & IRQF_SHARED) {
        local_irq_save(flags);
        action->handler(irq, dev_id);
        local_irq_restore(flags);
    }
#endif

    /*
     * The action has already been removed above, but the thread writes
     * its oneshot mask bit when it completes. Though request_mutex is
     * held across this which prevents __setup_irq() from handing out
     * the same bit to a newly requested action.
     */
    if (action->thread) {
        kthread_stop_put(action->thread);
        if (action->secondary && action->secondary->thread)
            kthread_stop_put(action->secondary->thread);
    }

    /* Last action releases resources */
    if (!desc->action) {
        /*
         * Reacquire bus lock as irq_release_resources() might
         * require it to deallocate resources over the slow bus.
         */
        chip_bus_lock(desc);
        /*
         * There is no interrupt on the fly anymore. Deactivate it
         * completely.
         */
        raw_spin_lock_irqsave(&desc->lock, flags);
        irq_domain_deactivate_irq(&desc->irq_data);
        raw_spin_unlock_irqrestore(&desc->lock, flags);

        irq_release_resources(desc);
        chip_bus_sync_unlock(desc);
        irq_remove_timings(desc);
    }

    mutex_unlock(&desc->request_mutex);

    irq_chip_pm_put(&desc->irq_data);
    module_put(desc->owner);
    kfree(action->secondary);
    return action;
}

/**
 *  free_irq - free an interrupt allocated with request_irq
 *  @irq: Interrupt line to free
 *  @dev_id: Device identity to free
 *
 *  Remove an interrupt handler. The handler is removed and if the
 *  interrupt line is no longer in use by any driver it is disabled.
 *  On a shared IRQ the caller must ensure the interrupt is disabled
 *  on the card it drives before calling this function. The function
 *  does not return until any executing interrupts for this IRQ
 *  have completed.
 *
 *  This function must not be called from interrupt context.
 *
 *  Returns the devname argument passed to request_irq.
 */
const void *free_irq(unsigned int irq, void *dev_id)
{
    struct irq_desc *desc = irq_to_desc(irq);
    struct irqaction *action;
    const char *devname;

    if (!desc || WARN_ON(irq_settings_is_per_cpu_devid(desc)))
        return NULL;

#ifdef CONFIG_SMP
    if (WARN_ON(desc->affinity_notify))
        desc->affinity_notify = NULL;
#endif

    action = __free_irq(desc, dev_id);

    if (!action)
        return NULL;

    devname = action->name;
    kfree(action);
    return devname;
}
