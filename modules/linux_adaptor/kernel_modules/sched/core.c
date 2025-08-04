#include <linux/highmem.h>
#include <linux/hrtimer_api.h>
#include <linux/ktime_api.h>
#include <linux/sched/signal.h>
#include <linux/syscalls_api.h>
#include <linux/debug_locks.h>
#include <linux/prefetch.h>
#include <linux/capability.h>
#include <linux/pgtable_api.h>
#include <linux/wait_bit.h>
#include <linux/jiffies.h>
#include <linux/spinlock_api.h>
#include <linux/cpumask_api.h>
#include <linux/lockdep_api.h>
#include <linux/hardirq.h>
#include <linux/softirq.h>
#include <linux/refcount_api.h>
#include <linux/topology.h>
#include <linux/sched/clock.h>
#include <linux/sched/cond_resched.h>
#include <linux/sched/cputime.h>
#include <linux/sched/debug.h>
#include <linux/sched/hotplug.h>
#include <linux/sched/init.h>
#include <linux/sched/isolation.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/mm.h>
#include <linux/sched/nohz.h>
#include <linux/sched/rseq_api.h>
#include <linux/sched/rt.h>

#include <linux/blkdev.h>
#include <linux/context_tracking.h>
#include <linux/cpuset.h>
#include <linux/delayacct.h>
#include <linux/init_task.h>
#include <linux/interrupt.h>
#include <linux/ioprio.h>
#include <linux/kallsyms.h>
#include <linux/kcov.h>
#include <linux/kprobes.h>
#include <linux/llist_api.h>
#include <linux/mmu_context.h>
#include <linux/mmzone.h>
#include <linux/mutex_api.h>
#include <linux/nmi.h>
#include <linux/nospec.h>
#include <linux/perf_event_api.h>
#include <linux/profile.h>
#include <linux/psi.h>
#include <linux/rcuwait_api.h>
#include <linux/rseq.h>
#include <linux/sched/wake_q.h>
#include <linux/scs.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/vtime.h>
#include <linux/wait_api.h>
#include <linux/workqueue_api.h>
#include <linux/mqueue.h>

#ifdef CONFIG_PREEMPT_DYNAMIC
# ifdef CONFIG_GENERIC_ENTRY
#  include <linux/entry-common.h>
# endif
#endif

#include <uapi/linux/sched/types.h>

#include <asm/irq_regs.h>
#include <asm/switch_to.h>
#include <asm/tlb.h>

#define CREATE_TRACE_POINTS
#include <linux/sched/rseq_api.h>
#include <trace/events/sched.h>
#include <trace/events/ipi.h>
#undef CREATE_TRACE_POINTS

#include "sched.h"
#include "stats.h"

#include "autogroup.h"
#include "pelt.h"
#include "smp.h"
#include "stats.h"

//#include "../workqueue_internal.h"
//#include "../../io_uring/io-wq.h"
//#include "../smpboot.h"

#include "../adaptor.h"

static struct signal_struct __init_signal = {
    .rlim = INIT_RLIMITS
};

static struct task_struct __init_task = {
    /*
#ifdef CONFIG_THREAD_INFO_IN_TASK
    .thread_info    = INIT_THREAD_INFO(init_task),
    .stack_refcount = REFCOUNT_INIT(1),
#endif
    */
    .signal     = &__init_signal,
    .nsproxy    = &init_nsproxy,
};

unsigned long init_current(unsigned long thread_id)
{
    struct task_struct *tsk = &__init_task;
    tsk->pid = thread_id;
    tsk->flags |= PF_KTHREAD;
    set_kthread_struct(tsk);
    __asm__ __volatile__ (
        "mv tp, %0"
        : : "rK" (tsk)
        : "memory"
    );
    printk("%s: init_task(%lu) ptr (0x%lx)\n", __func__, thread_id, tsk);
    return (unsigned long)tsk;
}

/**
 * wake_up_process - Wake up a specific process
 * @p: The process to be woken up.
 *
 * Attempt to wake up the nominated process and move it to the set of runnable
 * processes.
 *
 * Return: 1 if the process was woken up, 0 if it was already running.
 *
 * This function executes a full memory barrier before accessing the task state.
 */
int wake_up_process(struct task_struct *p)
{
    return try_to_wake_up(p, TASK_NORMAL, 0);
}

asmlinkage __visible void __sched schedule(void)
{
    printk("%s: current(0x%lx) state(%u)\n",
           __func__, current, READ_ONCE(current->__state));

    cl_resched((READ_ONCE(current->__state) == TASK_RUNNING));
}

int default_wake_function(wait_queue_entry_t *curr, unsigned mode, int wake_flags,
              void *key)
{
    WARN_ON_ONCE(IS_ENABLED(CONFIG_SCHED_DEBUG) && wake_flags & ~(WF_SYNC|WF_CURRENT_CPU));
    return try_to_wake_up(curr->private, mode, wake_flags);
}

int try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
{
    if (p == NULL) {
        PANIC("bad task pointer.");
    }
    printk("%s: task_ptr(%lx:%u) tid(%lu) current(%lx:%u)\n",
           __func__, p, p->__state, p->pid, current, current->__state);
#if 0
    if (p == current) {
        return 0;
    }
#endif
    if (p->__state == TASK_RUNNING) {
        return 0;
    }
    cl_wake_up(p->pid);
    return 1;
}

void __might_sleep(const char *file, int line)
{
    unsigned int state = get_current_state();
    /*
     * Blocking primitives will set (and therefore destroy) current->state,
     * since we will exit with TASK_RUNNING make sure we enter with it,
     * otherwise we will destroy state.
     */
    WARN_ONCE(state != TASK_RUNNING && current->task_state_change,
            "do not call blocking ops when !TASK_RUNNING; "
            "state=%x set at [<%p>] %pS\n", state,
            (void *)current->task_state_change,
            (void *)current->task_state_change);

    __might_resched(file, line, 0);
}

void __might_resched(const char *file, int line, unsigned int offsets)
{
    pr_err("%s: No impl.", __func__);
}

static void __sched notrace preempt_schedule_common(void)
{
#if 0
    do {
        /*
         * Because the function tracer can trace preempt_count_sub()
         * and it also uses preempt_enable/disable_notrace(), if
         * NEED_RESCHED is set, the preempt_enable_notrace() called
         * by the function tracer will call this function again and
         * cause infinite recursion.
         *
         * Preemption must be disabled here before the function
         * tracer can trace. Break up preempt_disable() into two
         * calls. One to disable preemption without fear of being
         * traced. The other to still record the preemption latency,
         * which can also be traced by the function tracer.
         */
        preempt_disable_notrace();
        preempt_latency_start(1);
        __schedule(SM_PREEMPT);
        preempt_latency_stop(1);
        preempt_enable_no_resched_notrace();

        /*
         * Check again in case we missed a preemption opportunity
         * between schedule and now.
         */
    } while (need_resched());
#endif
    PANIC("");
}

#if !defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC)
int __sched __cond_resched(void)
{
    if (should_resched(0) && !irqs_disabled()) {
        preempt_schedule_common();
        return 1;
    }
    /*
     * In preemptible kernels, ->rcu_read_lock_nesting tells the tick
     * whether the current CPU is in an RCU read-side critical section,
     * so the tick can report quiescent states even for CPUs looping
     * in kernel context.  In contrast, in non-preemptible kernels,
     * RCU readers leave no in-memory hints, which means that CPU-bound
     * processes executing in kernel context might never report an
     * RCU quiescent state.  Therefore, the following code causes
     * cond_resched() to report a quiescent state, but only when RCU
     * is in urgent need of one.
     */
#ifndef CONFIG_PREEMPT_RCU
    rcu_all_qs();
#endif
    return 0;
}
#endif

int io_schedule_prepare(void)
{
    int old_iowait = current->in_iowait;

    current->in_iowait = 1;
    blk_flush_plug(current->plug, true);
    return old_iowait;
}

void io_schedule_finish(int token)
{
    current->in_iowait = token;
}

void __sched io_schedule(void)
{
    int token;

    token = io_schedule_prepare();
    schedule();
    io_schedule_finish(token);
}

int wake_up_state(struct task_struct *p, unsigned int state)
{
    return try_to_wake_up(p, state, 0);
}

/*
 * This task is about to go to sleep on IO. Increment rq->nr_iowait so
 * that process accounting knows that this is a task in IO wait state.
 */
long __sched io_schedule_timeout(long timeout)
{
    int token;
    long ret;

    token = io_schedule_prepare();
    ret = schedule_timeout(timeout);
    io_schedule_finish(token);

    return ret;
}

/*
 * __cond_resched_lock() - if a reschedule is pending, drop the given lock,
 * call schedule, and on return reacquire the lock.
 *
 * This works OK both with and without CONFIG_PREEMPTION. We do strange low-level
 * operations here to prevent schedule() from being called twice (once via
 * spin_unlock(), once by hand).
 */
int __cond_resched_lock(spinlock_t *lock)
{
    int resched = should_resched(PREEMPT_LOCK_OFFSET);
    int ret = 0;

    lockdep_assert_held(lock);

    if (spin_needbreak(lock) || resched) {
        spin_unlock(lock);
        if (!_cond_resched())
            cpu_relax();
        ret = 1;
        spin_lock(lock);
    }
    return ret;
}

void __init sched_init(void)
{
    wait_bit_init();
}
