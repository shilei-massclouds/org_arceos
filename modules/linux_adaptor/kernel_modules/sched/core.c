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
    __init_task.pid = thread_id;
    __asm__ __volatile__ (
        "mv tp, %0"
        : : "rK" (tsk)
        : "memory"
    );
    pr_debug("%s: init_task(%lu) ptr (0x%lx)\n", __func__, thread_id, tsk);
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
    pr_err("%s: No impl.", __func__);
    return 0;
    //return try_to_wake_up(p, TASK_NORMAL, 0);
}

asmlinkage __visible void __sched schedule(void)
{
    pr_err("%s: ... state(%u) (%u)",
           __func__, READ_ONCE(current->__state), TASK_RUNNING);

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
    printk("%s: task_ptr(%lx) tid(%lu)\n", __func__, p, p->pid);
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

#if !defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC)
int __sched __cond_resched(void)
{
    pr_err("%s: No impl.", __func__);
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

void __init sched_init(void)
{
    wait_bit_init();
}
