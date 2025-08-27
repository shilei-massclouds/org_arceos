#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/local_lock.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/smp.h>
#include <linux/smpboot.h>
#include <linux/tick.h>
#include <linux/irq.h>
#include <linux/wait_bit.h>
#include <linux/workqueue.h>

#include <asm/softirq_stack.h>
#include <asm/stacktrace.h>

#define CREATE_TRACE_POINTS
#include <trace/events/irq.h>

#include "../adaptor.h"

static inline bool lockdep_softirq_start(void) { return false; }
static inline void lockdep_softirq_end(bool in_hardirq) { }

/*
 * We restart softirq processing for at most MAX_SOFTIRQ_RESTART times,
 * but break the loop if need_resched() is set or after 2 ms.
 * The MAX_SOFTIRQ_TIME provides a nice upper bound in most cases, but in
 * certain cases, such as stop_machine(), jiffies may cease to
 * increment and so we need the MAX_SOFTIRQ_RESTART limit as
 * well to make sure we eventually return from this method.
 *
 * These limits have been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
#define MAX_SOFTIRQ_TIME  msecs_to_jiffies(2)
#define MAX_SOFTIRQ_RESTART 10

#ifndef __ARCH_IRQ_STAT
DEFINE_PER_CPU_ALIGNED(irq_cpustat_t, irq_stat);
#endif

static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;

DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

const char * const softirq_to_name[NR_SOFTIRQS] = {
    "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL",
    "TASKLET", "SCHED", "HRTIMER", "RCU"
};

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static void wakeup_softirqd(void)
{
    pr_notice("%s: No impl.", __func__);
}

static inline void invoke_softirq(void)
{
    if (!force_irqthreads() || !__this_cpu_read(ksoftirqd)) {
#ifdef CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK
        /*
         * We can safely execute softirq on the current stack if
         * it is the irq stack, because it should be near empty
         * at this stage.
         */
        __do_softirq();
#else
        /*
         * Otherwise, irq_exit() is called on the task stack that can
         * be potentially deep already. So call softirq in its own stack
         * to prevent from any overrun.
         */
        do_softirq_own_stack();
#endif
    } else {
        wakeup_softirqd();
    }
}

void cl_invoke_softirq(void)
{
    invoke_softirq();
}

static void __local_bh_enable(unsigned int cnt)
{
    lockdep_assert_irqs_disabled();

    if (preempt_count() == cnt)
        trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());

    if (softirq_count() == (cnt & SOFTIRQ_MASK))
        lockdep_softirqs_on(_RET_IP_);

    __preempt_count_sub(cnt);
}

static inline void softirq_handle_begin(void)
{
    __local_bh_disable_ip(_RET_IP_, SOFTIRQ_OFFSET);
}

static inline void softirq_handle_end(void)
{
    __local_bh_enable(SOFTIRQ_OFFSET);
    WARN_ON_ONCE(in_interrupt());
}

static void handle_softirqs(bool ksirqd)
{
    unsigned long end = jiffies + MAX_SOFTIRQ_TIME;
    unsigned long old_flags = current->flags;
    int max_restart = MAX_SOFTIRQ_RESTART;
    struct softirq_action *h;
    bool in_hardirq;
    __u32 pending;
    int softirq_bit;

    /*
     * Mask out PF_MEMALLOC as the current task context is borrowed for the
     * softirq. A softirq handled, such as network RX, might set PF_MEMALLOC
     * again if the socket is related to swapping.
     */
    current->flags &= ~PF_MEMALLOC;

    pending = local_softirq_pending();

    softirq_handle_begin();
    in_hardirq = lockdep_softirq_start();
    account_softirq_enter(current);

restart:
    /* Reset the pending bitmask before enabling irqs */
    set_softirq_pending(0);

    local_irq_enable();

    h = softirq_vec;

    while ((softirq_bit = ffs(pending))) {
        unsigned int vec_nr;
        int prev_count;

        h += softirq_bit - 1;

        vec_nr = h - softirq_vec;
        prev_count = preempt_count();

        //kstat_incr_softirqs_this_cpu(vec_nr);

        trace_softirq_entry(vec_nr);
        h->action();
        trace_softirq_exit(vec_nr);
        if (unlikely(prev_count != preempt_count())) {
            pr_err("huh, entered softirq %u %s %p with preempt_count %08x, exited with %08x?\n",
                   vec_nr, softirq_to_name[vec_nr], h->action,
                   prev_count, preempt_count());
            preempt_count_set(prev_count);
        }
        h++;
        pending >>= softirq_bit;
    }

    if (!IS_ENABLED(CONFIG_PREEMPT_RT) && ksirqd)
        rcu_softirq_qs();

    local_irq_disable();

    pending = local_softirq_pending();
    if (pending) {
        if (time_before(jiffies, end) && !need_resched() &&
            --max_restart)
            goto restart;

        wakeup_softirqd();
    }

    account_softirq_exit(current);
    lockdep_softirq_end(in_hardirq);
    softirq_handle_end();
    current_restore_flags(old_flags, PF_MEMALLOC);
}

asmlinkage __visible void __softirq_entry __do_softirq(void)
{
    handle_softirqs(false);
}

static inline bool should_wake_ksoftirqd(void)
{
    return true;
}

void __raise_softirq_irqoff(unsigned int nr)
{
    lockdep_assert_irqs_disabled();
    trace_softirq_raise(nr);
    or_softirq_pending(1UL << nr);
}

/*
 * This function must run with irqs disabled!
 */
inline void raise_softirq_irqoff(unsigned int nr)
{
    __raise_softirq_irqoff(nr);

    /*
     * If we're in an interrupt or softirq, we're done
     * (this also catches softirq-disabled code). We will
     * actually run the softirq once we return from
     * the irq or softirq.
     *
     * Otherwise we wake up ksoftirqd to make sure we
     * schedule the softirq soon.
     */
    if (!in_interrupt() && should_wake_ksoftirqd())
        wakeup_softirqd();
}

void raise_softirq(unsigned int nr)
{
    unsigned long flags;

    pr_debug("%s: ...\n", __func__);
    local_irq_save(flags);
    raise_softirq_irqoff(nr);
    local_irq_restore(flags);
}

void open_softirq(int nr, void (*action)(void))
{
    softirq_vec[nr].action = action;
}

void __local_bh_enable_ip(unsigned long ip, unsigned int cnt)
{
    WARN_ON_ONCE(in_hardirq());
    lockdep_assert_irqs_enabled();
#ifdef CONFIG_TRACE_IRQFLAGS
    local_irq_disable();
#endif
    /*
     * Are softirqs going to be turned on now:
     */
    if (softirq_count() == SOFTIRQ_DISABLE_OFFSET)
        lockdep_softirqs_on(ip);
    /*
     * Keep preemption disabled until we are done with
     * softirq processing:
     */
    __preempt_count_sub(cnt - 1);

    if (unlikely(!in_interrupt() && local_softirq_pending())) {
        /*
         * Run softirq if any pending. And do it in its own stack
         * as we may be calling this deep in a task call stack already.
         */
        do_softirq();
    }

    preempt_count_dec();
#ifdef CONFIG_TRACE_IRQFLAGS
    local_irq_enable();
#endif
    preempt_check_resched();
}

asmlinkage __visible void do_softirq(void)
{
    __u32 pending;
    unsigned long flags;

    if (in_interrupt())
        return;

    local_irq_save(flags);

    pending = local_softirq_pending();

    if (pending)
        do_softirq_own_stack();

    local_irq_restore(flags);
}

static void ___do_softirq(struct pt_regs *regs)
{
    __do_softirq();
}

void do_softirq_own_stack(void)
{
    if (on_thread_stack()) {
        //call_on_irq_stack(NULL, ___do_softirq);
        PANIC("");
    } else {
        __do_softirq();
    }
}
