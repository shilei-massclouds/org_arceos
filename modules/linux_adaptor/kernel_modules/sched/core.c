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
#ifdef CONFIG_THREAD_INFO_IN_TASK
    .thread_info    = INIT_THREAD_INFO(__init_task),
    .stack_refcount = REFCOUNT_INIT(1),
#endif
    .signal     = &__init_signal,
    .nsproxy    = &init_nsproxy,
    .fs         = &init_fs,
    .files      = &init_files,
    RCU_POINTER_INITIALIZER(real_cred, &init_cred),
    RCU_POINTER_INITIALIZER(cred, &init_cred),
};

unsigned long init_current(unsigned long thread_id)
{
    struct task_struct *tsk = &__init_task;
    tsk->pid = thread_id;
    tsk->flags |= PF_KTHREAD;
    WRITE_ONCE(tsk->__state, TASK_RUNNING);
    set_kthread_struct(tsk);
    __asm__ __volatile__ (
        "mv tp, %0"
        : : "rK" (tsk)
        : "memory"
    );
    printk("%s: init_task(%lu) ptr (0x%lx)\n", __func__, thread_id, tsk);
    return (unsigned long)tsk;
}

unsigned long get_main_task_id()
{
    return __init_task.pid;
}

/*
 * Mark the task runnable.
 */
static inline void ttwu_do_wakeup(struct task_struct *p)
{
    WRITE_ONCE(p->__state, TASK_RUNNING);
    trace_sched_wakeup(p);
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
    pr_debug("%s: current(0x%lx) state(%u)\n",
             __func__, current, READ_ONCE(current->__state));

    cl_resched(READ_ONCE(current->__state));
}

int default_wake_function(wait_queue_entry_t *curr, unsigned mode, int wake_flags,
              void *key)
{
    WARN_ON_ONCE(IS_ENABLED(CONFIG_SCHED_DEBUG) && wake_flags & ~(WF_SYNC|WF_CURRENT_CPU));
    return try_to_wake_up(curr->private, mode, wake_flags);
}

static __always_inline
int __task_state_match(struct task_struct *p, unsigned int state)
{
    if (READ_ONCE(p->__state) & state)
        return 1;

    if (READ_ONCE(p->saved_state) & state)
        return -1;

    return 0;
}

static void
ttwu_stat(struct task_struct *p, int cpu, int wake_flags)
{
    pr_notice("%s: No impl.", __func__);
}

/*
 * Invoked from try_to_wake_up() to check whether the task can be woken up.
 *
 * The caller holds p::pi_lock if p != current or has preemption
 * disabled when p == current.
 *
 * The rules of saved_state:
 *
 *   The related locking code always holds p::pi_lock when updating
 *   p::saved_state, which means the code is fully serialized in both cases.
 *
 *   For PREEMPT_RT, the lock wait and lock wakeups happen via TASK_RTLOCK_WAIT.
 *   No other bits set. This allows to distinguish all wakeup scenarios.
 *
 *   For FREEZER, the wakeup happens via TASK_FROZEN. No other bits set. This
 *   allows us to prevent early wakeup of tasks before they can be run on
 *   asymmetric ISA architectures (eg ARMv9).
 */
static __always_inline
bool ttwu_state_match(struct task_struct *p, unsigned int state, int *success)
{
    int match;

    if (IS_ENABLED(CONFIG_DEBUG_PREEMPT)) {
        WARN_ON_ONCE((state & TASK_RTLOCK_WAIT) &&
                 state != TASK_RTLOCK_WAIT);
    }

    *success = !!(match = __task_state_match(p, state));

    /*
     * Saved state preserves the task state across blocking on
     * an RT lock or TASK_FREEZABLE tasks.  If the state matches,
     * set p::saved_state to TASK_RUNNING, but do not wake the task
     * because it waits for a lock wakeup or __thaw_task(). Also
     * indicate success because from the regular waker's point of
     * view this has succeeded.
     *
     * After acquiring the lock the task will restore p::__state
     * from p::saved_state which ensures that the regular
     * wakeup is not lost. The restore will also set
     * p::saved_state to TASK_RUNNING so any further tests will
     * not result in false positives vs. @success
     */
    if (match < 0)
        p->saved_state = TASK_RUNNING;

    return match > 0;
}

/*
 * Consider @p being inside a wait loop:
 *
 *   for (;;) {
 *      set_current_state(TASK_UNINTERRUPTIBLE);
 *
 *      if (CONDITION)
 *         break;
 *
 *      schedule();
 *   }
 *   __set_current_state(TASK_RUNNING);
 *
 * between set_current_state() and schedule(). In this case @p is still
 * runnable, so all that needs doing is change p->state back to TASK_RUNNING in
 * an atomic manner.
 *
 * By taking task_rq(p)->lock we serialize against schedule(), if @p->on_rq
 * then schedule() must still happen and p->state can be changed to
 * TASK_RUNNING. Otherwise we lost the race, schedule() has happened, and we
 * need to do a full wakeup with enqueue.
 *
 * Returns: %true when the wakeup is done,
 *          %false otherwise.
 */
static int ttwu_runnable(struct task_struct *p, int wake_flags)
{
    PANIC("");
}

static bool ttwu_queue_wakelist(struct task_struct *p, int cpu, int wake_flags)
{
#if 0
    if (sched_feat(TTWU_QUEUE) && ttwu_queue_cond(p, cpu)) {
        sched_clock_cpu(cpu); /* Sync clocks across CPUs */
        __ttwu_queue_wakelist(p, cpu, wake_flags);
        return true;
    }
#endif

    pr_notice("%s: No impl.", __func__);
    return false;
}

/*
 * The caller (fork, wakeup) owns p->pi_lock, ->cpus_ptr is stable.
 */
static inline
int select_task_rq(struct task_struct *p, int cpu, int *wake_flags)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

void set_task_cpu(struct task_struct *p, unsigned int new_cpu)
{
#ifdef CONFIG_SCHED_DEBUG
    unsigned int state = READ_ONCE(p->__state);

    /*
     * We should never call set_task_cpu() on a blocked task,
     * ttwu() will sort out the placement.
     */
    WARN_ON_ONCE(state != TASK_RUNNING && state != TASK_WAKING && !p->on_rq);

#ifdef CONFIG_LOCKDEP
    /*
     * The caller should hold either p->pi_lock or rq->lock, when changing
     * a task's CPU. ->pi_lock for waking tasks, rq->lock for runnable tasks.
     *
     * sched_move_task() holds both and thus holding either pins the cgroup,
     * see task_group().
     *
     * Furthermore, all task_rq users should acquire both locks, see
     * task_rq_lock().
     */
    WARN_ON_ONCE(debug_locks && !(lockdep_is_held(&p->pi_lock) ||
                      lockdep_is_held(__rq_lockp(task_rq(p)))));
#endif
    /*
     * Clearly, migrating tasks to offline CPUs is a fairly daft thing.
     */
    WARN_ON_ONCE(!cpu_online(new_cpu));

#endif

    trace_sched_migrate_task(p, new_cpu);

    if (task_cpu(p) != new_cpu) {
        p->se.nr_migrations++;
        rseq_migrate(p);
        perf_event_task_migrate(p);
    }

	smp_wmb();
	WRITE_ONCE(task_thread_info(p)->cpu, new_cpu);
	p->wake_cpu = new_cpu;
}

static void
ttwu_do_activate(struct task_struct *p, int wake_flags)
{
    int en_flags = ENQUEUE_WAKEUP | ENQUEUE_NOCLOCK;

#ifdef CONFIG_SMP
    if (wake_flags & WF_RQ_SELECTED)
        en_flags |= ENQUEUE_RQ_SELECTED;
    if (wake_flags & WF_MIGRATED)
        en_flags |= ENQUEUE_MIGRATED;
    else
#endif
    if (p->in_iowait) {
        delayacct_blkio_end(p);
    }

    ttwu_do_wakeup(p);
}

static void ttwu_queue(struct task_struct *p, int cpu, int wake_flags)
{
    if (ttwu_queue_wakelist(p, cpu, wake_flags))
        return;

    ttwu_do_activate(p, wake_flags);
}

/**
 * try_to_wake_up - wake up a thread
 * @p: the thread to be awakened
 * @state: the mask of task states that can be woken
 * @wake_flags: wake modifier flags (WF_*)
 *
 * Conceptually does:
 *
 *   If (@state & @p->state) @p->state = TASK_RUNNING.
 *
 * If the task was not queued/runnable, also place it back on a runqueue.
 *
 * This function is atomic against schedule() which would dequeue the task.
 *
 * It issues a full memory barrier before accessing @p->state, see the comment
 * with set_current_state().
 *
 * Uses p->pi_lock to serialize against concurrent wake-ups.
 *
 * Relies on p->pi_lock stabilizing:
 *  - p->sched_class
 *  - p->cpus_ptr
 *  - p->sched_task_group
 * in order to do migration, see its use of select_task_rq()/set_task_cpu().
 *
 * Tries really hard to only take one task_rq(p)->lock for performance.
 * Takes rq->lock in:
 *  - ttwu_runnable()    -- old rq, unavoidable, see comment there;
 *  - ttwu_queue()       -- new rq, for enqueue of the task;
 *  - psi_ttwu_dequeue() -- much sadness :-( accounting will kill us.
 *
 * As a consequence we race really badly with just about everything. See the
 * many memory barriers and their comments for details.
 *
 * Return: %true if @p->state changes (an actual wakeup was done),
 *     %false otherwise.
 */
int try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
{
    guard(preempt)();
    int cpu, success = 0;

    if (p == NULL) {
        PANIC("bad task pointer.");
    }
    pr_debug("%s: task_ptr(%lx:%u) tid(%lu) current(%lx:%u)\n",
             __func__, p, p->__state, p->pid, current, current->__state);

    wake_flags |= WF_TTWU;

    if (p == current) {
        /*
         * We're waking current, this means 'p->on_rq' and 'task_cpu(p)
         * == smp_processor_id()'. Together this means we can special
         * case the whole 'p->on_rq && ttwu_runnable()' case below
         * without taking any locks.
         *
         * Specifically, given current runs ttwu() we must be before
         * schedule()'s block_task(), as such this must not observe
         * sched_delayed.
         *
         * In particular:
         *  - we rely on Program-Order guarantees for all the ordering,
         *  - we're serialized against set_special_state() by virtue of
         *    it disabling IRQs (this allows not taking ->pi_lock).
         */
        SCHED_WARN_ON(p->se.sched_delayed);
        if (!ttwu_state_match(p, state, &success))
            goto out;

        trace_sched_waking(p);
        ttwu_do_wakeup(p);
        goto out;
    }


    /*
     * If we are going to wake up a thread waiting for CONDITION we
     * need to ensure that CONDITION=1 done by the caller can not be
     * reordered with p->state check below. This pairs with smp_store_mb()
     * in set_current_state() that the waiting thread does.
     */
    scoped_guard (raw_spinlock_irqsave, &p->pi_lock) {
        smp_mb__after_spinlock();
        if (!ttwu_state_match(p, state, &success))
            break;

        trace_sched_waking(p);

        /*
         * Ensure we load p->on_rq _after_ p->state, otherwise it would
         * be possible to, falsely, observe p->on_rq == 0 and get stuck
         * in smp_cond_load_acquire() below.
         *
         * sched_ttwu_pending()         try_to_wake_up()
         *   STORE p->on_rq = 1           LOAD p->state
         *   UNLOCK rq->lock
         *
         * __schedule() (switch to task 'p')
         *   LOCK rq->lock            smp_rmb();
         *   smp_mb__after_spinlock();
         *   UNLOCK rq->lock
         *
         * [task p]
         *   STORE p->state = UNINTERRUPTIBLE     LOAD p->on_rq
         *
         * Pairs with the LOCK+smp_mb__after_spinlock() on rq->lock in
         * __schedule().  See the comment for smp_mb__after_spinlock().
         *
         * A similar smp_rmb() lives in __task_needs_rq_lock().
         */
        smp_rmb();
        if (READ_ONCE(p->on_rq) && ttwu_runnable(p, wake_flags))
            break;

#ifdef CONFIG_SMP
        /*
         * Ensure we load p->on_cpu _after_ p->on_rq, otherwise it would be
         * possible to, falsely, observe p->on_cpu == 0.
         *
         * One must be running (->on_cpu == 1) in order to remove oneself
         * from the runqueue.
         *
         * __schedule() (switch to task 'p')    try_to_wake_up()
         *   STORE p->on_cpu = 1          LOAD p->on_rq
         *   UNLOCK rq->lock
         *
         * __schedule() (put 'p' to sleep)
         *   LOCK rq->lock            smp_rmb();
         *   smp_mb__after_spinlock();
         *   STORE p->on_rq = 0           LOAD p->on_cpu
         *
         * Pairs with the LOCK+smp_mb__after_spinlock() on rq->lock in
         * __schedule().  See the comment for smp_mb__after_spinlock().
         *
         * Form a control-dep-acquire with p->on_rq == 0 above, to ensure
         * schedule()'s deactivate_task() has 'happened' and p will no longer
         * care about it's own p->state. See the comment in __schedule().
         */
        smp_acquire__after_ctrl_dep();

        /*
         * We're doing the wakeup (@success == 1), they did a dequeue (p->on_rq
         * == 0), which means we need to do an enqueue, change p->state to
         * TASK_WAKING such that we can unlock p->pi_lock before doing the
         * enqueue, such as ttwu_queue_wakelist().
         */
        WRITE_ONCE(p->__state, TASK_WAKING);

        /*
         * If the owning (remote) CPU is still in the middle of schedule() with
         * this task as prev, considering queueing p on the remote CPUs wake_list
         * which potentially sends an IPI instead of spinning on p->on_cpu to
         * let the waker make forward progress. This is safe because IRQs are
         * disabled and the IPI will deliver after on_cpu is cleared.
         *
         * Ensure we load task_cpu(p) after p->on_cpu:
         *
         * set_task_cpu(p, cpu);
         *   STORE p->cpu = @cpu
         * __schedule() (switch to task 'p')
         *   LOCK rq->lock
         *   smp_mb__after_spin_lock()      smp_cond_load_acquire(&p->on_cpu)
         *   STORE p->on_cpu = 1        LOAD p->cpu
         *
         * to ensure we observe the correct CPU on which the task is currently
         * scheduling.
         */
        if (smp_load_acquire(&p->on_cpu) &&
            ttwu_queue_wakelist(p, task_cpu(p), wake_flags))
            break;

        /*
         * If the owning (remote) CPU is still in the middle of schedule() with
         * this task as prev, wait until it's done referencing the task.
         *
         * Pairs with the smp_store_release() in finish_task().
         *
         * This ensures that tasks getting woken will be fully ordered against
         * their previous state and preserve Program Order.
         */
        smp_cond_load_acquire(&p->on_cpu, !VAL);

        cpu = select_task_rq(p, p->wake_cpu, &wake_flags);
        if (task_cpu(p) != cpu) {
            if (p->in_iowait) {
                delayacct_blkio_end(p);
                //atomic_dec(&task_rq(p)->nr_iowait);
            }

            wake_flags |= WF_MIGRATED;
            psi_ttwu_dequeue(p);
            set_task_cpu(p, cpu);
        }
#else
        cpu = task_cpu(p);
#endif /* CONFIG_SMP */

        ttwu_queue(p, cpu, wake_flags);
    }
out:
    if (success)
        ttwu_stat(p, task_cpu(p), wake_flags);

    return success;
}

void __might_sleep(const char *file, int line)
{
    unsigned int state = get_current_state();
#if 0
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
#endif

    __might_resched(file, line, 0);
}

void __might_resched(const char *file, int line, unsigned int offsets)
{
    pr_notice("%s: No impl.", __func__);
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

void cl_set_task_state(struct task_struct *p, unsigned int state)
{
    if (p == NULL) {
        PANIC("bad task ptr.");
    }

    if (state != TASK_RUNNING &&
        state != TASK_INTERRUPTIBLE &&
        state != TASK_UNINTERRUPTIBLE) {
        PANIC("bad task state.");
    }

    WRITE_ONCE(p->__state, state);
}

void wake_up_q(struct wake_q_head *head)
{
    PANIC("");
}

void __init sched_init(void)
{
    wait_bit_init();
}
