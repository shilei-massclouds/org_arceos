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

static struct task_struct task_dummy;
struct task_struct *get_current(void)
{
    task_dummy.signal = &signal_dummy;
    return &task_dummy;
}

asmlinkage __visible void __sched schedule(void)
{
    log_error("%s: No impl.", __func__);
}

int __sched _cond_resched(void)
{
    log_error("%s: No impl.", __func__);
}
