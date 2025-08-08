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

/**
 * mutex_trylock - try to acquire the mutex, without waiting
 * @lock: the mutex to be acquired
 *
 * Try to acquire the mutex atomically. Returns 1 if the mutex
 * has been acquired successfully, and 0 on contention.
 *
 * NOTE: this function follows the spin_trylock() convention, so
 * it is negated from the down_trylock() return values! Be careful
 * about this when converting semaphore users to mutexes.
 *
 * This function must not be used in interrupt context. The
 * mutex must be released by the same task that acquired it.
 */
int __sched mutex_trylock(struct mutex *lock)
{
#if 0
    bool locked;

    MUTEX_WARN_ON(lock->magic != lock);

    locked = __mutex_trylock(lock);
    if (locked)
        mutex_acquire(&lock->dep_map, 0, 1, _RET_IP_);

    return locked;
#endif
    pr_err("=== NOTE ===: %s: No impl.\n", __func__);
    return true;
}
