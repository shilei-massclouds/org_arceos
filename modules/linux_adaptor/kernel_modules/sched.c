#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/signal.h>
#include <linux/resource.h>
#include <linux/fs.h>
#include <linux/mqueue.h>
#include <linux/blkdev.h>
#include <linux/wait.h>

#include "booter.h"

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
    return (unsigned long)__task;
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

int io_schedule_prepare(void)
{
    int old_iowait = current->in_iowait;

    current->in_iowait = 1;
    blk_schedule_flush_plug(current);

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
