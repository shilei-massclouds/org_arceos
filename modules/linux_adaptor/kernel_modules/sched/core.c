#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/debug.h>
#include <linux/resource.h>
#include <linux/fs.h>
#include <linux/mqueue.h>
#include <linux/mmu_context.h>

#include "sched.h"
#include "../adaptor.h"

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
    struct task_struct *tsk = &task_dummy;
    task_dummy.pid = thread_id;
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

void __init sched_init(void)
{
    wait_bit_init();
}
