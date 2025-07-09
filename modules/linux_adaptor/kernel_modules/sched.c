#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/signal.h>
#include <linux/resource.h>
#include <linux/fs.h>
#include <linux/mqueue.h>

#include "booter.h"

void __might_sleep(const char *file, int line, int preempt_offset)
{
    /*
     * Blocking primitives will set (and therefore destroy) current->state,
     * since we will exit with TASK_RUNNING make sure we enter with it,
     * otherwise we will destroy state.
     */
    WARN_ONCE(current->state != TASK_RUNNING && current->task_state_change,
            "do not call blocking ops when !TASK_RUNNING; "
            "state=%lx set at [<%p>] %pS\n",
            current->state,
            (void *)current->task_state_change,
            (void *)current->task_state_change);

    ___might_sleep(file, line, preempt_offset);
}

void ___might_sleep(const char *file, int line, int preempt_offset)
{
    log_error("%s: No impl.", __func__);
}

static struct signal_struct signal_dummy = {
    .rlim = INIT_RLIMITS
};

static struct task_struct task_dummy = {
    /*
#ifdef CONFIG_THREAD_INFO_IN_TASK
    .thread_info    = INIT_THREAD_INFO(init_task),
    .stack_refcount = REFCOUNT_INIT(1),
#endif
*/

    .signal = &signal_dummy
};

unsigned long init_current(unsigned long thread_id)
{
    struct task_struct *__task = &task_dummy;
    task_dummy.pid = thread_id;
    __asm__ __volatile__ (
        "mv tp, %0"
        : : "rK" (__task)
        : "memory"
    );
    log_error("%s: %lx\n", __func__, __task);
    return __task;
}

asmlinkage __visible void __sched schedule(void)
{
    log_error("%s: ... state(%u) (%u)",
              __func__, READ_ONCE(current->state), TASK_RUNNING);

    cl_resched((READ_ONCE(current->state) == TASK_RUNNING));
}

int __sched _cond_resched(void)
{
    log_error("%s: No impl.", __func__);
    return 0;
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
    log_error("%s: No impl.", __func__);
    return 0;
}

void __init sched_init(void)
{
    wait_bit_init();
}
