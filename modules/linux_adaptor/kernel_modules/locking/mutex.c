#include <linux/mutex.h>
#include <linux/sched/debug.h>

#include "../adaptor.h"

#include <linux/mutex.h>
#include <linux/ww_mutex.h>
#include <linux/sched/signal.h>
#include <linux/sched/rt.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/debug.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/debug_locks.h>
#include <linux/osq_lock.h>

#define CREATE_TRACE_POINTS
#include <trace/events/lock.h>

#include "mutex.h"

#ifdef CONFIG_DEBUG_MUTEXES
# define MUTEX_WARN_ON(cond) DEBUG_LOCKS_WARN_ON(cond)
#else
# define MUTEX_WARN_ON(cond)
#endif

void
__mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
{
    pr_err("%s: No impl.\n", __func__);
}

void __sched mutex_lock(struct mutex *lock)
{
    pr_err("%s: No impl.\n", __func__);
}

void __sched mutex_unlock(struct mutex *lock)
{
    pr_err("%s: No impl.\n", __func__);
}

/**
 * mutex_lock_io() - Acquire the mutex and mark the process as waiting for I/O
 * @lock: The mutex to be acquired.
 *
 * Lock the mutex like mutex_lock().  While the task is waiting for this
 * mutex, it will be accounted as being in the IO wait state by the
 * scheduler.
 *
 * Context: Process context.
 */
void __sched mutex_lock_io(struct mutex *lock)
{
    int token;

    token = io_schedule_prepare();
    mutex_lock(lock);
    io_schedule_finish(token);
}

bool mutex_is_locked(struct mutex *lock)
{
    pr_err("=== NOTE ===: %s: No impl.\n", __func__);
    return true;
    //return __mutex_owner(lock) != NULL;
}
