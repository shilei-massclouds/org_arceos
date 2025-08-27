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

#include "../adaptor.h"

__visible u64 jiffies_64 __cacheline_aligned_in_smp = INITIAL_JIFFIES;

#define MOD_TIMER_PENDING_ONLY      0x01
#define MOD_TIMER_REDUCE            0x02
#define MOD_TIMER_NOTPENDING        0x04

/* Clock divisor for the next level */
#define LVL_CLK_SHIFT   3
#define LVL_CLK_DIV (1UL << LVL_CLK_SHIFT)
#define LVL_CLK_MASK    (LVL_CLK_DIV - 1)
#define LVL_SHIFT(n)    ((n) * LVL_CLK_SHIFT)
#define LVL_GRAN(n) (1UL << LVL_SHIFT(n))

/*
 * The time start value for each level to select the bucket at enqueue
 * time. We start from the last possible delta of the previous level
 * so that we can later add an extra LVL_GRAN(n) to n (see calc_index()).
 */
#define LVL_START(n)    ((LVL_SIZE - 1) << (((n) - 1) * LVL_CLK_SHIFT))

/* Size of each clock level */
#define LVL_BITS    6
#define LVL_SIZE    (1UL << LVL_BITS)
#define LVL_MASK    (LVL_SIZE - 1)
#define LVL_OFFS(n) ((n) * LVL_SIZE)

/* Level depth */
#if HZ > 100
# define LVL_DEPTH  9
# else
# define LVL_DEPTH  8
#endif

/* The cutoff (max. capacity of the wheel) */
#define WHEEL_TIMEOUT_CUTOFF    (LVL_START(LVL_DEPTH))
#define WHEEL_TIMEOUT_MAX   (WHEEL_TIMEOUT_CUTOFF - LVL_GRAN(LVL_DEPTH - 1))

/*
 * The resulting wheel size. If NOHZ is configured we allocate two
 * wheels so we have a separate storage for the deferrable timers.
 */
#define WHEEL_SIZE  (LVL_SIZE * LVL_DEPTH)

#ifdef CONFIG_NO_HZ_COMMON
/*
 * If multiple bases need to be locked, use the base ordering for lock
 * nesting, i.e. lowest number first.
 */
# define NR_BASES   3
# define BASE_LOCAL 0
# define BASE_GLOBAL    1
# define BASE_DEF   2
#else
# define NR_BASES   1
# define BASE_LOCAL 0
# define BASE_GLOBAL    0
# define BASE_DEF   0
#endif

/**
 * struct timer_base - Per CPU timer base (number of base depends on config)
 * @lock:       Lock protecting the timer_base
 * @running_timer:  When expiring timers, the lock is dropped. To make
 *          sure not to race against deleting/modifying a
 *          currently running timer, the pointer is set to the
 *          timer, which expires at the moment. If no timer is
 *          running, the pointer is NULL.
 * @expiry_lock:    PREEMPT_RT only: Lock is taken in softirq around
 *          timer expiry callback execution and when trying to
 *          delete a running timer and it wasn't successful in
 *          the first glance. It prevents priority inversion
 *          when callback was preempted on a remote CPU and a
 *          caller tries to delete the running timer. It also
 *          prevents a life lock, when the task which tries to
 *          delete a timer preempted the softirq thread which
 *          is running the timer callback function.
 * @timer_waiters:  PREEMPT_RT only: Tells, if there is a waiter
 *          waiting for the end of the timer callback function
 *          execution.
 * @clk:        clock of the timer base; is updated before enqueue
 *          of a timer; during expiry, it is 1 offset ahead of
 *          jiffies to avoid endless requeuing to current
 *          jiffies
 * @next_expiry:    expiry value of the first timer; it is updated when
 *          finding the next timer and during enqueue; the
 *          value is not valid, when next_expiry_recalc is set
 * @cpu:        Number of CPU the timer base belongs to
 * @next_expiry_recalc: States, whether a recalculation of next_expiry is
 *          required. Value is set true, when a timer was
 *          deleted.
 * @is_idle:        Is set, when timer_base is idle. It is triggered by NOHZ
 *          code. This state is only used in standard
 *          base. Deferrable timers, which are enqueued remotely
 *          never wake up an idle CPU. So no matter of supporting it
 *          for this base.
 * @timers_pending: Is set, when a timer is pending in the base. It is only
 *          reliable when next_expiry_recalc is not set.
 * @pending_map:    bitmap of the timer wheel; each bit reflects a
 *          bucket of the wheel. When a bit is set, at least a
 *          single timer is enqueued in the related bucket.
 * @vectors:        Array of lists; Each array member reflects a bucket
 *          of the timer wheel. The list contains all timers
 *          which are enqueued into a specific bucket.
 */
struct timer_base {
    raw_spinlock_t      lock;
    struct timer_list   *running_timer;
#ifdef CONFIG_PREEMPT_RT
    spinlock_t      expiry_lock;
    atomic_t        timer_waiters;
#endif
    unsigned long       clk;
    unsigned long       next_expiry;
    unsigned int        cpu;
    bool            next_expiry_recalc;
    bool            is_idle;
    bool            timers_pending;
    DECLARE_BITMAP(pending_map, WHEEL_SIZE);
    struct hlist_head   vectors[WHEEL_SIZE];
} ____cacheline_aligned;

static DEFINE_PER_CPU(struct timer_base, timer_bases[NR_BASES]);

/*
 * Since schedule_timeout()'s timer is defined on the stack, it must store
 * the target task on the stack as well.
 */
struct process_timer {
    struct timer_list timer;
    struct task_struct *task;
};

static inline void timer_base_init_expiry_lock(struct timer_base *base) { }
static inline void timer_base_lock_expiry(struct timer_base *base) { }
static inline void timer_base_unlock_expiry(struct timer_base *base) { }
static inline void timer_sync_wait_running(struct timer_base *base) { }
static inline void del_timer_wait_running(struct timer_list *timer) { }

static inline void debug_timer_init(struct timer_list *timer) { }
static inline void debug_timer_activate(struct timer_list *timer) { }
static inline void debug_timer_deactivate(struct timer_list *timer) { }
static inline void debug_timer_assert_init(struct timer_list *timer) { }

static inline void debug_assert_init(struct timer_list *timer)
{
    debug_timer_assert_init(timer);
}

static inline bool is_timers_nohz_active(void)
{
    pr_notice("%s: No impl.", __func__);
    return false;
    //return static_branch_unlikely(&timers_nohz_active);
}

static inline unsigned int timer_get_idx(struct timer_list *timer)
{
    return (timer->flags & TIMER_ARRAYMASK) >> TIMER_ARRAYSHIFT;
}

static inline void timer_set_idx(struct timer_list *timer, unsigned int idx)
{
    timer->flags = (timer->flags & ~TIMER_ARRAYMASK) |
            idx << TIMER_ARRAYSHIFT;
}

static inline struct timer_base *get_timer_cpu_base(u32 tflags, u32 cpu)
{
    int index = tflags & TIMER_PINNED ? BASE_LOCAL : BASE_GLOBAL;
    struct timer_base *base;

    base = per_cpu_ptr(&timer_bases[index], cpu);

    /*
     * If the timer is deferrable and NO_HZ_COMMON is set then we need
     * to use the deferrable base.
     */
    if (IS_ENABLED(CONFIG_NO_HZ_COMMON) && (tflags & TIMER_DEFERRABLE))
        base = per_cpu_ptr(&timer_bases[BASE_DEF], cpu);
    return base;
}

static inline struct timer_base *get_timer_this_cpu_base(u32 tflags)
{
    int index = tflags & TIMER_PINNED ? BASE_LOCAL : BASE_GLOBAL;
    struct timer_base *base;

    base = this_cpu_ptr(&timer_bases[index]);

    /*
     * If the timer is deferrable and NO_HZ_COMMON is set then we need
     * to use the deferrable base.
     */
    if (IS_ENABLED(CONFIG_NO_HZ_COMMON) && (tflags & TIMER_DEFERRABLE))
        base = this_cpu_ptr(&timer_bases[BASE_DEF]);
    return base;
}

static inline struct timer_base *get_timer_base(u32 tflags)
{
    return get_timer_cpu_base(tflags, tflags & TIMER_CPUMASK);
}

/*
 * Helper function to calculate the array index for a given expiry
 * time.
 */
static inline unsigned calc_index(unsigned long expires, unsigned lvl,
                  unsigned long *bucket_expiry)
{

    /*
     * The timer wheel has to guarantee that a timer does not fire
     * early. Early expiry can happen due to:
     * - Timer is armed at the edge of a tick
     * - Truncation of the expiry time in the outer wheel levels
     *
     * Round up with level granularity to prevent this.
     */
    expires = (expires >> LVL_SHIFT(lvl)) + 1;
    *bucket_expiry = expires << LVL_SHIFT(lvl);
    return LVL_OFFS(lvl) + (expires & LVL_MASK);
}

static int calc_wheel_index(unsigned long expires, unsigned long clk,
                unsigned long *bucket_expiry)
{
    unsigned long delta = expires - clk;
    unsigned int idx;

    if (delta < LVL_START(1)) {
        idx = calc_index(expires, 0, bucket_expiry);
    } else if (delta < LVL_START(2)) {
        idx = calc_index(expires, 1, bucket_expiry);
    } else if (delta < LVL_START(3)) {
        idx = calc_index(expires, 2, bucket_expiry);
    } else if (delta < LVL_START(4)) {
        idx = calc_index(expires, 3, bucket_expiry);
    } else if (delta < LVL_START(5)) {
        idx = calc_index(expires, 4, bucket_expiry);
    } else if (delta < LVL_START(6)) {
        idx = calc_index(expires, 5, bucket_expiry);
    } else if (delta < LVL_START(7)) {
        idx = calc_index(expires, 6, bucket_expiry);
    } else if (LVL_DEPTH > 8 && delta < LVL_START(8)) {
        idx = calc_index(expires, 7, bucket_expiry);
    } else if ((long) delta < 0) {
        idx = clk & LVL_MASK;
        *bucket_expiry = clk;
    } else {
        /*
         * Force expire obscene large timeouts to expire at the
         * capacity limit of the wheel.
         */
        if (delta >= WHEEL_TIMEOUT_CUTOFF)
            expires = clk + WHEEL_TIMEOUT_MAX;

        idx = calc_index(expires, LVL_DEPTH - 1, bucket_expiry);
    }
    return idx;
}

static inline void __forward_timer_base(struct timer_base *base,
                    unsigned long basej)
{
    /*
     * Check whether we can forward the base. We can only do that when
     * @basej is past base->clk otherwise we might rewind base->clk.
     */
    if (time_before_eq(basej, base->clk))
        return;

    /*
     * If the next expiry value is > jiffies, then we fast forward to
     * jiffies otherwise we forward to the next expiry value.
     */
    if (time_after(base->next_expiry, basej)) {
        base->clk = basej;
    } else {
        if (WARN_ON_ONCE(time_before(base->next_expiry, base->clk)))
            return;
        base->clk = base->next_expiry;
    }
    pr_debug("%s: basej(%lu) timer(%lu)\n", __func__, basej, base->clk);

}

static inline void forward_timer_base(struct timer_base *base)
{
    __forward_timer_base(base, READ_ONCE(jiffies));
}

static inline void detach_timer(struct timer_list *timer, bool clear_pending)
{
    struct hlist_node *entry = &timer->entry;

    //debug_deactivate(timer);

    __hlist_del(entry);
    if (clear_pending)
        entry->pprev = NULL;
    entry->next = LIST_POISON2;
}

static int detach_if_pending(struct timer_list *timer, struct timer_base *base,
                 bool clear_pending)
{
    unsigned idx = timer_get_idx(timer);

    if (!timer_pending(timer))
        return 0;

    if (hlist_is_singular_node(&timer->entry, base->vectors + idx)) {
        __clear_bit(idx, base->pending_map);
        base->next_expiry_recalc = true;
    }

    detach_timer(timer, clear_pending);
    return 1;
}

/*
 * We are using hashed locking: Holding per_cpu(timer_bases[x]).lock means
 * that all timers which are tied to this base are locked, and the base itself
 * is locked too.
 *
 * So __run_timers/migrate_timers can safely modify all timers which could
 * be found in the base->vectors array.
 *
 * When a timer is migrating then the TIMER_MIGRATING flag is set and we need
 * to wait until the migration is done.
 */
static struct timer_base *lock_timer_base(struct timer_list *timer,
                      unsigned long *flags)
    __acquires(timer->base->lock)
{
    for (;;) {
        struct timer_base *base;
        u32 tf;

        /*
         * We need to use READ_ONCE() here, otherwise the compiler
         * might re-read @tf between the check for TIMER_MIGRATING
         * and spin_lock().
         */
        tf = READ_ONCE(timer->flags);

        if (!(tf & TIMER_MIGRATING)) {
            base = get_timer_base(tf);
            raw_spin_lock_irqsave(&base->lock, *flags);
            if (timer->flags == tf)
                return base;
            raw_spin_unlock_irqrestore(&base->lock, *flags);
        }
        cpu_relax();

        PANIC("LOOP");
    }
    PANIC("");
}

static void
trigger_dyntick_cpu(struct timer_base *base, struct timer_list *timer)
{
    /*
     * Deferrable timers do not prevent the CPU from entering dynticks and
     * are not taken into account on the idle/nohz_full path. An IPI when a
     * new deferrable timer is enqueued will wake up the remote CPU but
     * nothing will be done with the deferrable timer base. Therefore skip
     * the remote IPI for deferrable timers completely.
     */
    if (!is_timers_nohz_active() || timer->flags & TIMER_DEFERRABLE)
        return;

    /*
     * We might have to IPI the remote CPU if the base is idle and the
     * timer is pinned. If it is a non pinned timer, it is only queued
     * on the remote CPU, when timer was running during queueing. Then
     * everything is handled by remote CPU anyway. If the other CPU is
     * on the way to idle then it can't set base->is_idle as we hold
     * the base lock:
     */
    if (base->is_idle) {
        WARN_ON_ONCE(!(timer->flags & TIMER_PINNED ||
                   tick_nohz_full_cpu(base->cpu)));
        wake_up_nohz_cpu(base->cpu);
    }
}

/*
 * Enqueue the timer into the hash bucket, mark it pending in
 * the bitmap, store the index in the timer flags then wake up
 * the target CPU if needed.
 */
static void enqueue_timer(struct timer_base *base, struct timer_list *timer,
              unsigned int idx, unsigned long bucket_expiry)
{
    pr_debug("%s: ...\n", __func__);
    hlist_add_head(&timer->entry, base->vectors + idx);
    __set_bit(idx, base->pending_map);
    timer_set_idx(timer, idx);

    trace_timer_start(timer, bucket_expiry);

    /*
     * Check whether this is the new first expiring timer. The
     * effective expiry time of the timer is required here
     * (bucket_expiry) instead of timer->expires.
     */
    if (time_before(bucket_expiry, base->next_expiry)) {
        /*
         * Set the next expiry time and kick the CPU so it
         * can reevaluate the wheel:
         */
        WRITE_ONCE(base->next_expiry, bucket_expiry);
        base->timers_pending = true;
        base->next_expiry_recalc = false;
        trigger_dyntick_cpu(base, timer);
    }
}

static void internal_add_timer(struct timer_base *base, struct timer_list *timer)
{
    unsigned long bucket_expiry;
    unsigned int idx;

    idx = calc_wheel_index(timer->expires, base->clk, &bucket_expiry);
    enqueue_timer(base, timer, idx, bucket_expiry);
}

static inline int
__mod_timer(struct timer_list *timer, unsigned long expires, unsigned int options)
{
    unsigned long clk = 0, flags, bucket_expiry;
    struct timer_base *base, *new_base;
    unsigned int idx = UINT_MAX;
    int ret = 0;

    debug_assert_init(timer);

    /*
     * This is a common optimization triggered by the networking code - if
     * the timer is re-modified to have the same timeout or ends up in the
     * same array bucket then just return:
     */
    if (!(options & MOD_TIMER_NOTPENDING) && timer_pending(timer)) {
        PANIC("stage1");
    } else {
        base = lock_timer_base(timer, &flags);
        /*
         * Has @timer been shutdown? This needs to be evaluated
         * while holding base lock to prevent a race against the
         * shutdown code.
         */
        if (!timer->function)
            goto out_unlock;

        forward_timer_base(base);
    }

    ret = detach_if_pending(timer, base, false);
    if (!ret && (options & MOD_TIMER_PENDING_ONLY))
        goto out_unlock;

    new_base = get_timer_this_cpu_base(timer->flags);

    if (base != new_base) {
        /*
         * We are trying to schedule the timer on the new base.
         * However we can't change timer's base while it is running,
         * otherwise timer_delete_sync() can't detect that the timer's
         * handler yet has not finished. This also guarantees that the
         * timer is serialized wrt itself.
         */
        if (likely(base->running_timer != timer)) {
            /* See the comment in lock_timer_base() */
            timer->flags |= TIMER_MIGRATING;

            raw_spin_unlock(&base->lock);
            base = new_base;
            raw_spin_lock(&base->lock);
            WRITE_ONCE(timer->flags,
                   (timer->flags & ~TIMER_BASEMASK) | base->cpu);
            forward_timer_base(base);
        }
    }

    debug_timer_activate(timer);

    timer->expires = expires;
    /*
     * If 'idx' was calculated above and the base time did not advance
     * between calculating 'idx' and possibly switching the base, only
     * enqueue_timer() is required. Otherwise we need to (re)calculate
     * the wheel index via internal_add_timer().
     */
    if (idx != UINT_MAX && clk == base->clk)
        enqueue_timer(base, timer, idx, bucket_expiry);
    else
        internal_add_timer(base, timer);

out_unlock:
    raw_spin_unlock_irqrestore(&base->lock, flags);

    return ret;
}

/**
 * __try_to_del_timer_sync - Internal function: Try to deactivate a timer
 * @timer:  Timer to deactivate
 * @shutdown:   If true, this indicates that the timer is about to be
 *      shutdown permanently.
 *
 * If @shutdown is true then @timer->function is set to NULL under the
 * timer base lock which prevents further rearming of the timer. Any
 * attempt to rearm @timer after this function returns will be silently
 * ignored.
 *
 * This function cannot guarantee that the timer cannot be rearmed
 * right after dropping the base lock if @shutdown is false. That
 * needs to be prevented by the calling code if necessary.
 *
 * Return:
 * * %0  - The timer was not pending
 * * %1  - The timer was pending and deactivated
 * * %-1 - The timer callback function is running on a different CPU
 */
static int __try_to_del_timer_sync(struct timer_list *timer, bool shutdown)
{
    struct timer_base *base;
    unsigned long flags;
    int ret = -1;

    debug_assert_init(timer);

    base = lock_timer_base(timer, &flags);

    if (base->running_timer != timer)
        ret = detach_if_pending(timer, base, true);
    if (shutdown)
        timer->function = NULL;

    raw_spin_unlock_irqrestore(&base->lock, flags);

    return ret;
}

/**
 * __timer_delete_sync - Internal function: Deactivate a timer and wait
 *           for the handler to finish.
 * @timer:  The timer to be deactivated
 * @shutdown:   If true, @timer->function will be set to NULL under the
 *      timer base lock which prevents rearming of @timer
 *
 * If @shutdown is not set the timer can be rearmed later. If the timer can
 * be rearmed concurrently, i.e. after dropping the base lock then the
 * return value is meaningless.
 *
 * If @shutdown is set then @timer->function is set to NULL under timer
 * base lock which prevents rearming of the timer. Any attempt to rearm
 * a shutdown timer is silently ignored.
 *
 * If the timer should be reused after shutdown it has to be initialized
 * again.
 *
 * Return:
 * * %0 - The timer was not pending
 * * %1 - The timer was pending and deactivated
 */
static int __timer_delete_sync(struct timer_list *timer, bool shutdown)
{
    int ret;

#ifdef CONFIG_LOCKDEP
    unsigned long flags;

    /*
     * If lockdep gives a backtrace here, please reference
     * the synchronization rules above.
     */
    local_irq_save(flags);
    lock_map_acquire(&timer->lockdep_map);
    lock_map_release(&timer->lockdep_map);
    local_irq_restore(flags);
#endif
    /*
     * don't use it in hardirq context, because it
     * could lead to deadlock.
     */
    WARN_ON(in_hardirq() && !(timer->flags & TIMER_IRQSAFE));

    /*
     * Must be able to sleep on PREEMPT_RT because of the slowpath in
     * del_timer_wait_running().
     */
    if (IS_ENABLED(CONFIG_PREEMPT_RT) && !(timer->flags & TIMER_IRQSAFE))
        lockdep_assert_preemption_enabled();

    do {
        ret = __try_to_del_timer_sync(timer, shutdown);

        if (unlikely(ret < 0)) {
            del_timer_wait_running(timer);
            cpu_relax();
        }
    } while (ret < 0);

    return ret;
}
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
    return __timer_delete_sync(timer, false);
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
    return __mod_timer(timer, expires, 0);
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

    debug_assert_init(timer);

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
        base = lock_timer_base(timer, &flags);
        ret = detach_if_pending(timer, base, true);
        if (shutdown)
            timer->function = NULL;
        raw_spin_unlock_irqrestore(&base->lock, flags);
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
    if (WARN_ON_ONCE(timer_pending(timer)))
        return;
    __mod_timer(timer, timer->expires, MOD_TIMER_NOTPENDING);
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
    if (WARN_ON_ONCE(timer_pending(timer)))
        return;
    timer->flags &= ~TIMER_PINNED;
    __mod_timer(timer, timer->expires, MOD_TIMER_NOTPENDING);
}

static void process_timeout(struct timer_list *t)
{
    struct process_timer *timeout = from_timer(timeout, t, timer);

    wake_up_process(timeout->task);
}

/**
 * schedule_timeout - sleep until timeout
 * @timeout: timeout value in jiffies
 *
 * Make the current task sleep until @timeout jiffies have elapsed.
 * The function behavior depends on the current task state
 * (see also set_current_state() description):
 *
 * %TASK_RUNNING - the scheduler is called, but the task does not sleep
 * at all. That happens because sched_submit_work() does nothing for
 * tasks in %TASK_RUNNING state.
 *
 * %TASK_UNINTERRUPTIBLE - at least @timeout jiffies are guaranteed to
 * pass before the routine returns unless the current task is explicitly
 * woken up, (e.g. by wake_up_process()).
 *
 * %TASK_INTERRUPTIBLE - the routine may return early if a signal is
 * delivered to the current task or the current task is explicitly woken
 * up.
 *
 * The current task state is guaranteed to be %TASK_RUNNING when this
 * routine returns.
 *
 * Specifying a @timeout value of %MAX_SCHEDULE_TIMEOUT will schedule
 * the CPU away without a bound on the timeout. In this case the return
 * value will be %MAX_SCHEDULE_TIMEOUT.
 *
 * Returns 0 when the timer has expired otherwise the remaining time in
 * jiffies will be returned. In all cases the return value is guaranteed
 * to be non-negative.
 */
signed long __sched schedule_timeout(signed long timeout)
{
    struct process_timer timer;
    unsigned long expire;

    pr_debug("%s: =================> timeout(%ld)", __func__, timeout);
    switch (timeout)
    {
    case MAX_SCHEDULE_TIMEOUT:
        /*
         * These two special cases are useful to be comfortable
         * in the caller. Nothing more. We could take
         * MAX_SCHEDULE_TIMEOUT from one of the negative value
         * but I' d like to return a valid offset (>=0) to allow
         * the caller to do everything it want with the retval.
         */
        schedule();
        goto out;
    default:
        /*
         * Another bit of PARANOID. Note that the retval will be
         * 0 since no piece of kernel is supposed to do a check
         * for a negative retval of schedule_timeout() (since it
         * should never happens anyway). You just have the printk()
         * that will tell you if something is gone wrong and where.
         */
        if (timeout < 0) {
            printk(KERN_ERR "schedule_timeout: wrong timeout "
                "value %lx\n", timeout);
            dump_stack();
            __set_current_state(TASK_RUNNING);
            goto out;
        }
    }

    expire = timeout + jiffies;

    timer.task = current;
    timer_setup_on_stack(&timer.timer, process_timeout, 0);
    __mod_timer(&timer.timer, expire, MOD_TIMER_NOTPENDING);
    schedule();
    del_timer_sync(&timer.timer);

    /* Remove the timer from the object tracker */
    destroy_timer_on_stack(&timer.timer);

    timeout = expire - jiffies;

 out:
    return timeout < 0 ? 0 : timeout;
}

void add_timer_on(struct timer_list *timer, int cpu)
{
    struct timer_base *new_base, *base;
    unsigned long flags;

    debug_assert_init(timer);

    if (WARN_ON_ONCE(timer_pending(timer)))
        return;

    /* Make sure timer flags have TIMER_PINNED flag set */
    timer->flags |= TIMER_PINNED;

    new_base = get_timer_cpu_base(timer->flags, cpu);

    /*
     * If @timer was on a different CPU, it should be migrated with the
     * old base locked to prevent other operations proceeding with the
     * wrong base locked.  See lock_timer_base().
     */
    base = lock_timer_base(timer, &flags);
    /*
     * Has @timer been shutdown? This needs to be evaluated while
     * holding base lock to prevent a race against the shutdown code.
     */
    if (!timer->function)
        goto out_unlock;

    if (base != new_base) {
        timer->flags |= TIMER_MIGRATING;

        raw_spin_unlock(&base->lock);
        base = new_base;
        raw_spin_lock(&base->lock);
        WRITE_ONCE(timer->flags,
               (timer->flags & ~TIMER_BASEMASK) | cpu);
    }
    forward_timer_base(base);

    debug_timer_activate(timer);
    internal_add_timer(base, timer);
out_unlock:
    raw_spin_unlock_irqrestore(&base->lock, flags);
}

static int collect_expired_timers(struct timer_base *base,
                  struct hlist_head *heads)
{
    unsigned long clk = base->clk = base->next_expiry;
    struct hlist_head *vec;
    int i, levels = 0;
    unsigned int idx;

    for (i = 0; i < LVL_DEPTH; i++) {
        idx = (clk & LVL_MASK) + i * LVL_SIZE;

        if (__test_and_clear_bit(idx, base->pending_map)) {
            vec = base->vectors + idx;
            hlist_move_list(vec, heads++);
            levels++;
        }
        /* Is it time to look at the next level? */
        if (clk & LVL_CLK_MASK)
            break;
        /* Shift clock for the next level granularity */
        clk >>= LVL_CLK_SHIFT;
    }
    return levels;
}

/*
 * Find the next pending bucket of a level. Search from level start (@offset)
 * + @clk upwards and if nothing there, search from start of the level
 * (@offset) up to @offset + clk.
 */
static int next_pending_bucket(struct timer_base *base, unsigned offset,
                   unsigned clk)
{
    unsigned pos, start = offset + clk;
    unsigned end = offset + LVL_SIZE;

    pos = find_next_bit(base->pending_map, end, start);
    if (pos < end)
        return pos - start;

    pos = find_next_bit(base->pending_map, start, offset);
    return pos < start ? pos + LVL_SIZE - start : -1;
}

/*
 * Search the first expiring timer in the various clock levels. Caller must
 * hold base->lock.
 *
 * Store next expiry time in base->next_expiry.
 */
static void timer_recalc_next_expiry(struct timer_base *base)
{
    unsigned long clk, next, adj;
    unsigned lvl, offset = 0;

    next = base->clk + NEXT_TIMER_MAX_DELTA;
    clk = base->clk;
    for (lvl = 0; lvl < LVL_DEPTH; lvl++, offset += LVL_SIZE) {
        int pos = next_pending_bucket(base, offset, clk & LVL_MASK);
        unsigned long lvl_clk = clk & LVL_CLK_MASK;

        if (pos >= 0) {
            unsigned long tmp = clk + (unsigned long) pos;

            tmp <<= LVL_SHIFT(lvl);
            if (time_before(tmp, next))
                next = tmp;

            /*
             * If the next expiration happens before we reach
             * the next level, no need to check further.
             */
            if (pos <= ((LVL_CLK_DIV - lvl_clk) & LVL_CLK_MASK))
                break;
        }
        /*
         * Clock for the next level. If the current level clock lower
         * bits are zero, we look at the next level as is. If not we
         * need to advance it by one because that's going to be the
         * next expiring bucket in that level. base->clk is the next
         * expiring jiffy. So in case of:
         *
         * LVL5 LVL4 LVL3 LVL2 LVL1 LVL0
         *  0    0    0    0    0    0
         *
         * we have to look at all levels @index 0. With
         *
         * LVL5 LVL4 LVL3 LVL2 LVL1 LVL0
         *  0    0    0    0    0    2
         *
         * LVL0 has the next expiring bucket @index 2. The upper
         * levels have the next expiring bucket @index 1.
         *
         * In case that the propagation wraps the next level the same
         * rules apply:
         *
         * LVL5 LVL4 LVL3 LVL2 LVL1 LVL0
         *  0    0    0    0    F    2
         *
         * So after looking at LVL0 we get:
         *
         * LVL5 LVL4 LVL3 LVL2 LVL1
         *  0    0    0    1    0
         *
         * So no propagation from LVL1 to LVL2 because that happened
         * with the add already, but then we need to propagate further
         * from LVL2 to LVL3.
         *
         * So the simple check whether the lower bits of the current
         * level are 0 or not is sufficient for all cases.
         */
        adj = lvl_clk ? 1 : 0;
        clk >>= LVL_CLK_SHIFT;
        clk += adj;
    }

    WRITE_ONCE(base->next_expiry, next);
    base->next_expiry_recalc = false;
    base->timers_pending = !(next == base->clk + NEXT_TIMER_MAX_DELTA);
}

static void call_timer_fn(struct timer_list *timer,
              void (*fn)(struct timer_list *),
              unsigned long baseclk)
{
    int count = preempt_count();

#ifdef CONFIG_LOCKDEP
    /*
     * It is permissible to free the timer from inside the
     * function that is called from it, this we need to take into
     * account for lockdep too. To avoid bogus "held lock freed"
     * warnings as well as problems when looking into
     * timer->lockdep_map, make a copy and use that here.
     */
    struct lockdep_map lockdep_map;

    lockdep_copy_map(&lockdep_map, &timer->lockdep_map);
#endif
    /*
     * Couple the lock chain with the lock chain at
     * timer_delete_sync() by acquiring the lock_map around the fn()
     * call here and in timer_delete_sync().
     */
    lock_map_acquire(&lockdep_map);

    trace_timer_expire_entry(timer, baseclk);
    fn(timer);
    trace_timer_expire_exit(timer);

    lock_map_release(&lockdep_map);

    if (count != preempt_count()) {
        WARN_ONCE(1, "timer: %pS preempt leak: %08x -> %08x\n",
              fn, count, preempt_count());
        /*
         * Restore the preempt count. That gives us a decent
         * chance to survive and extract information. If the
         * callback kept a lock held, bad luck, but not worse
         * than the BUG() we had.
         */
        preempt_count_set(count);
    }
}

static void expire_timers(struct timer_base *base, struct hlist_head *head)
{
    /*
     * This value is required only for tracing. base->clk was
     * incremented directly before expire_timers was called. But expiry
     * is related to the old base->clk value.
     */
    unsigned long baseclk = base->clk - 1;

    while (!hlist_empty(head)) {
        struct timer_list *timer;
        void (*fn)(struct timer_list *);

        timer = hlist_entry(head->first, struct timer_list, entry);

        base->running_timer = timer;
        detach_timer(timer, true);

        fn = timer->function;

        if (WARN_ON_ONCE(!fn)) {
            /* Should never happen. Emphasis on should! */
            base->running_timer = NULL;
            continue;
        }

        if (timer->flags & TIMER_IRQSAFE) {
            raw_spin_unlock(&base->lock);
            call_timer_fn(timer, fn, baseclk);
            raw_spin_lock(&base->lock);
            base->running_timer = NULL;
        } else {
            raw_spin_unlock_irq(&base->lock);
            call_timer_fn(timer, fn, baseclk);
            raw_spin_lock_irq(&base->lock);
            base->running_timer = NULL;
            timer_sync_wait_running(base);
        }
    }
}

/**
 * __run_timers - run all expired timers (if any) on this CPU.
 * @base: the timer vector to be processed.
 */
static inline void __run_timers(struct timer_base *base)
{
    struct hlist_head heads[LVL_DEPTH];
    int levels;

    lockdep_assert_held(&base->lock);

    if (base->running_timer)
        return;

    while (time_after_eq(jiffies, base->clk) &&
           time_after_eq(jiffies, base->next_expiry)) {
        levels = collect_expired_timers(base, heads);
        pr_debug("%s: levels(%u)\n", __func__, levels);
        /*
         * The two possible reasons for not finding any expired
         * timer at this clk are that all matching timers have been
         * dequeued or no timer has been queued since
         * base::next_expiry was set to base::clk +
         * NEXT_TIMER_MAX_DELTA.
         */
        WARN_ON_ONCE(!levels && !base->next_expiry_recalc
                 && base->timers_pending);
        /*
         * While executing timers, base->clk is set 1 offset ahead of
         * jiffies to avoid endless requeuing to current jiffies.
         */
        base->clk++;
        timer_recalc_next_expiry(base);

        while (levels--)
            expire_timers(base, heads + levels);
    }
}

static void __run_timer_base(struct timer_base *base)
{
    pr_debug("%s: jiffies(%lu) next_expiry(%lu)\n",
             __func__, jiffies, base->next_expiry);

    /* Can race against a remote CPU updating next_expiry under the lock */
    if (time_before(jiffies, READ_ONCE(base->next_expiry)))
        return;

    timer_base_lock_expiry(base);
    raw_spin_lock_irq(&base->lock);
    __run_timers(base);
    raw_spin_unlock_irq(&base->lock);
    timer_base_unlock_expiry(base);
}

static void run_timer_base(int index)
{
    struct timer_base *base = this_cpu_ptr(&timer_bases[index]);

    __run_timer_base(base);
}

/*
 * This function runs timers and the timer-tq in bottom half context.
 */
static __latent_entropy void run_timer_softirq(void)
{
    run_timer_base(BASE_LOCAL);
    if (IS_ENABLED(CONFIG_NO_HZ_COMMON)) {
        run_timer_base(BASE_GLOBAL);
        run_timer_base(BASE_DEF);

        if (is_timers_nohz_active())
            tmigr_handle_remote();
    }
}

/*
 * Called by the local, per-CPU timer interrupt on SMP.
 */
static void run_local_timers(void)
{
    struct timer_base *base = this_cpu_ptr(&timer_bases[BASE_LOCAL]);

    hrtimer_run_queues();

    for (int i = 0; i < NR_BASES; i++, base++) {
        /*
         * Raise the softirq only if required.
         *
         * timer_base::next_expiry can be written by a remote CPU while
         * holding the lock. If this write happens at the same time than
         * the lockless local read, sanity checker could complain about
         * data corruption.
         *
         * There are two possible situations where
         * timer_base::next_expiry is written by a remote CPU:
         *
         * 1. Remote CPU expires global timers of this CPU and updates
         * timer_base::next_expiry of BASE_GLOBAL afterwards in
         * next_timer_interrupt() or timer_recalc_next_expiry(). The
         * worst outcome is a superfluous raise of the timer softirq
         * when the not yet updated value is read.
         *
         * 2. A new first pinned timer is enqueued by a remote CPU
         * and therefore timer_base::next_expiry of BASE_LOCAL is
         * updated. When this update is missed, this isn't a
         * problem, as an IPI is executed nevertheless when the CPU
         * was idle before. When the CPU wasn't idle but the update
         * is missed, then the timer would expire one jiffy late -
         * bad luck.
         *
         * Those unlikely corner cases where the worst outcome is only a
         * one jiffy delay or a superfluous raise of the softirq are
         * not that expensive as doing the check always while holding
         * the lock.
         *
         * Possible remote writers are using WRITE_ONCE(). Local reader
         * uses therefore READ_ONCE().
         */
        pr_debug("%s: jiffies(%lu) next_expiry(%lu)\n",
                 __func__, jiffies, READ_ONCE(base->next_expiry));

        if (time_after_eq(jiffies, READ_ONCE(base->next_expiry)) ||
            (i == BASE_DEF && tmigr_requires_handle_remote())) {
            raise_softirq(TIMER_SOFTIRQ);
            return;
        }
    }
}

void cl_run_local_timers(void)
{
    if (clinux_starting == 0) {
        return;
    }

    do_timer(1);
    run_local_timers();
}

void __init init_timers(void)
{
    //init_timer_cpus();
    //posix_cputimers_init_work();
    open_softirq(TIMER_SOFTIRQ, run_timer_softirq);
}
