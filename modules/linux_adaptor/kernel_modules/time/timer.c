#include <linux/kernel_stat.h>
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pid_namespace.h>
#include <linux/notifier.h>
#include <linux/thread_info.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/posix-timers.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/tick.h>
#include <linux/kallsyms.h>
#include <linux/irq_work.h>
#include <linux/sched/signal.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/nohz.h>
#include <linux/sched/debug.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/random.h>
#include <linux/sysctl.h>

#include <linux/uaccess.h>
#include <asm/unistd.h>
#include <asm/div64.h>
#include <asm/timex.h>
#include <asm/io.h>

#include "tick-internal.h"
#include "timer_migration.h"

#define CREATE_TRACE_POINTS
#include <trace/events/timer.h>

/**
 * timer_delete_sync - Deactivate a timer and wait for the handler to finish.
 * @timer:  The timer to be deactivated
 *
 * Synchronization rules: Callers must prevent restarting of the timer,
 * otherwise this function is meaningless. It must not be called from
 * interrupt contexts unless the timer is an irqsafe one. The caller must
 * not hold locks which would prevent completion of the timer's callback
 * function. The timer's handler must not call add_timer_on(). Upon exit
 * the timer is not queued and the handler is not running on any CPU.
 *
 * For !irqsafe timers, the caller must not hold locks that are held in
 * interrupt context. Even if the lock has nothing to do with the timer in
 * question.  Here's why::
 *
 *    CPU0                             CPU1
 *    ----                             ----
 *                                     <SOFTIRQ>
 *                                       call_timer_fn();
 *                                       base->running_timer = mytimer;
 *    spin_lock_irq(somelock);
 *                                     <IRQ>
 *                                        spin_lock(somelock);
 *    timer_delete_sync(mytimer);
 *    while (base->running_timer == mytimer);
 *
 *
 * Now timer_delete_sync() will never return and never release somelock.
 * The interrupt on the other CPU is waiting to grab somelock but it has
 * interrupted the softirq that CPU0 is waiting to finish.
 *
 * This function cannot guarantee that the timer is not rearmed again by
 * some concurrent or preempting code, right after it dropped the base
 * lock. If there is the possibility of a concurrent rearm then the return
 * value of the function is meaningless.
 *
 * If such a guarantee is needed, e.g. for teardown situations then use
 * timer_shutdown_sync() instead.
 *
 * Return:
 * * %0 - The timer was not pending
 * * %1 - The timer was pending and deactivated
 */
int timer_delete_sync(struct timer_list *timer)
{
    pr_err("%s: No impl.", __func__);
    return 0;
    //return __timer_delete_sync(timer, false);
}

/**
 * mod_timer - Modify a timer's timeout
 * @timer:  The timer to be modified
 * @expires:    New absolute timeout in jiffies
 *
 * mod_timer(timer, expires) is equivalent to:
 *
 *     del_timer(timer); timer->expires = expires; add_timer(timer);
 *
 * mod_timer() is more efficient than the above open coded sequence. In
 * case that the timer is inactive, the del_timer() part is a NOP. The
 * timer is in any case activated with the new expiry time @expires.
 *
 * Note that if there are multiple unserialized concurrent users of the
 * same timer, then mod_timer() is the only safe way to modify the timeout,
 * since add_timer() cannot modify an already running timer.
 *
 * If @timer->function == NULL then the start operation is silently
 * discarded. In this case the return value is 0 and meaningless.
 *
 * Return:
 * * %0 - The timer was inactive and started or was in shutdown
 *    state and the operation was discarded
 * * %1 - The timer was active and requeued to expire at @expires or
 *    the timer was active and not modified because @expires did
 *    not change the effective expiry time
 */
int mod_timer(struct timer_list *timer, unsigned long expires)
{
    pr_err("%s: No impl.", __func__);
    return 0;
    //return __mod_timer(timer, expires, 0);
}

/**
 * __timer_delete - Internal function: Deactivate a timer
 * @timer:  The timer to be deactivated
 * @shutdown:   If true, this indicates that the timer is about to be
 *      shutdown permanently.
 *
 * If @shutdown is true then @timer->function is set to NULL under the
 * timer base lock which prevents further rearming of the time. In that
 * case any attempt to rearm @timer after this function returns will be
 * silently ignored.
 *
 * Return:
 * * %0 - The timer was not pending
 * * %1 - The timer was pending and deactivated
 */
static int __timer_delete(struct timer_list *timer, bool shutdown)
{
    struct timer_base *base;
    unsigned long flags;
    int ret = 0;

#if 0
    debug_assert_init(timer);
#endif

    /*
     * If @shutdown is set then the lock has to be taken whether the
     * timer is pending or not to protect against a concurrent rearm
     * which might hit between the lockless pending check and the lock
     * acquisition. By taking the lock it is ensured that such a newly
     * enqueued timer is dequeued and cannot end up with
     * timer->function == NULL in the expiry code.
     *
     * If timer->function is currently executed, then this makes sure
     * that the callback cannot requeue the timer.
     */
    if (timer_pending(timer) || shutdown) {
#if 0
        base = lock_timer_base(timer, &flags);
        ret = detach_if_pending(timer, base, true);
#endif
        if (shutdown)
            timer->function = NULL;
#if 0
        raw_spin_unlock_irqrestore(&base->lock, flags);
#endif
    }

    return ret;
}

/**
 * timer_delete - Deactivate a timer
 * @timer:  The timer to be deactivated
 *
 * The function only deactivates a pending timer, but contrary to
 * timer_delete_sync() it does not take into account whether the timer's
 * callback function is concurrently executed on a different CPU or not.
 * It neither prevents rearming of the timer.  If @timer can be rearmed
 * concurrently then the return value of this function is meaningless.
 *
 * Return:
 * * %0 - The timer was not pending
 * * %1 - The timer was pending and deactivated
 */
int timer_delete(struct timer_list *timer)
{
    return __timer_delete(timer, false);
}

static inline void debug_timer_init(struct timer_list *timer) { }

static inline void debug_init(struct timer_list *timer)
{
    debug_timer_init(timer);
    trace_timer_init(timer);
}

static void do_init_timer(struct timer_list *timer,
              void (*func)(struct timer_list *),
              unsigned int flags,
              const char *name, struct lock_class_key *key)
{
    timer->entry.pprev = NULL;
    timer->function = func;
    if (WARN_ON_ONCE(flags & ~TIMER_INIT_FLAGS))
        flags &= TIMER_INIT_FLAGS;
    timer->flags = flags | raw_smp_processor_id();
    lockdep_init_map(&timer->lockdep_map, name, key, 0);
}

/**
 * init_timer_key - initialize a timer
 * @timer: the timer to be initialized
 * @func: timer callback function
 * @flags: timer flags
 * @name: name of the timer
 * @key: lockdep class key of the fake lock used for tracking timer
 *       sync lock dependencies
 *
 * init_timer_key() must be done to a timer prior to calling *any* of the
 * other timer functions.
 */
void init_timer_key(struct timer_list *timer,
            void (*func)(struct timer_list *), unsigned int flags,
            const char *name, struct lock_class_key *key)
{
    debug_init(timer);
    do_init_timer(timer, func, flags, name, key);
}

static unsigned long round_jiffies_common(unsigned long j, int cpu,
        bool force_up)
{
    int rem;
    unsigned long original = j;

    /*
     * We don't want all cpus firing their timers at once hitting the
     * same lock or cachelines, so we skew each extra cpu with an extra
     * 3 jiffies. This 3 jiffies came originally from the mm/ code which
     * already did this.
     * The skew is done by adding 3*cpunr, then round, then subtract this
     * extra offset again.
     */
    j += cpu * 3;

    rem = j % HZ;

    /*
     * If the target jiffy is just after a whole second (which can happen
     * due to delays of the timer irq, long irq off times etc etc) then
     * we should round down to the whole second, not up. Use 1/4th second
     * as cutoff for this rounding as an extreme upper bound for this.
     * But never round down if @force_up is set.
     */
    if (rem < HZ/4 && !force_up) /* round down */
        j = j - rem;
    else /* round up */
        j = j - rem + HZ;

    /* now that we have rounded, subtract the extra skew again */
    j -= cpu * 3;

    /*
     * Make sure j is still in the future. Otherwise return the
     * unmodified value.
     */
    return time_is_after_jiffies(j) ? j : original;
}

/**
 * round_jiffies_up - function to round jiffies up to a full second
 * @j: the time in (absolute) jiffies that should be rounded
 *
 * This is the same as round_jiffies() except that it will never
 * round down.  This is useful for timeouts for which the exact time
 * of firing does not matter too much, as long as they don't fire too
 * early.
 */
unsigned long round_jiffies_up(unsigned long j)
{
    return round_jiffies_common(j, raw_smp_processor_id(), true);
}

/**
 * add_timer - Start a timer
 * @timer:  The timer to be started
 *
 * Start @timer to expire at @timer->expires in the future. @timer->expires
 * is the absolute expiry time measured in 'jiffies'. When the timer expires
 * timer->function(timer) will be invoked from soft interrupt context.
 *
 * The @timer->expires and @timer->function fields must be set prior
 * to calling this function.
 *
 * If @timer->function == NULL then the start operation is silently
 * discarded.
 *
 * If @timer->expires is already in the past @timer will be queued to
 * expire at the next timer tick.
 *
 * This can only operate on an inactive timer. Attempts to invoke this on
 * an active timer are rejected with a warning.
 */
void add_timer(struct timer_list *timer)
{
    pr_err("%s: No impl.", __func__);
#if 0
    if (WARN_ON_ONCE(timer_pending(timer)))
        return;
    __mod_timer(timer, timer->expires, MOD_TIMER_NOTPENDING);
#endif
}

/**
 * add_timer_global() - Start a timer without TIMER_PINNED flag set
 * @timer:  The timer to be started
 *
 * Same as add_timer() except that the timer flag TIMER_PINNED is unset.
 *
 * See add_timer() for further details.
 */
void add_timer_global(struct timer_list *timer)
{
    pr_err("%s: No impl.", __func__);
#if 0
    if (WARN_ON_ONCE(timer_pending(timer)))
        return;
    timer->flags &= ~TIMER_PINNED;
    __mod_timer(timer, timer->expires, MOD_TIMER_NOTPENDING);
#endif
}
