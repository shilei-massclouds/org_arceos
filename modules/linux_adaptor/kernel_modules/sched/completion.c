#include <linux/completion.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/cpuset.h>

#include "sched.h"

#include "../adaptor.h"

static inline long __sched
do_wait_for_common(struct completion *x,
           long (*action)(long), long timeout, int state)
{
    if (!x->done) {
        DECLARE_SWAITQUEUE(wait);

        do {
            if (signal_pending_state(state, current)) {
                timeout = -ERESTARTSYS;
                break;
            }
            __prepare_to_swait(&x->wait, &wait);
            __set_current_state(state);
            raw_spin_unlock_irq(&x->wait.lock);
            timeout = action(timeout);
            raw_spin_lock_irq(&x->wait.lock);
        } while (!x->done && timeout);
        __finish_swait(&x->wait, &wait);
        if (!x->done)
            return timeout;
    }
    if (x->done != UINT_MAX)
        x->done--;
    return timeout ?: 1;
}

static inline long __sched
__wait_for_common(struct completion *x,
          long (*action)(long), long timeout, int state)
{
    pr_debug("%s: timeout(%lu)", __func__, timeout);
    might_sleep();

    complete_acquire(x);

    raw_spin_lock_irq(&x->wait.lock);
    timeout = do_wait_for_common(x, action, timeout, state);
    raw_spin_unlock_irq(&x->wait.lock);

    complete_release(x);

    return timeout;
}

static long __sched
wait_for_common_io(struct completion *x, long timeout, int state)
{
    return __wait_for_common(x, io_schedule_timeout, timeout, state);
}

/**
 * complete_all: - signals all threads waiting on this completion
 * @x:  holds the state of this particular completion
 *
 * This will wake up all threads waiting on this particular completion event.
 *
 * If this function wakes up a task, it executes a full memory barrier before
 * accessing the task state.
 *
 * Since complete_all() sets the completion of @x permanently to done
 * to allow multiple waiters to finish, a call to reinit_completion()
 * must be used on @x if @x is to be used again. The code must make
 * sure that all waiters have woken and finished before reinitializing
 * @x. Also note that the function completion_done() can not be used
 * to know if there are still waiters after complete_all() has been called.
 */
void complete_all(struct completion *x)
{
    unsigned long flags;

    lockdep_assert_RT_in_threaded_ctx();

    raw_spin_lock_irqsave(&x->wait.lock, flags);
    x->done = UINT_MAX;
    swake_up_all_locked(&x->wait);
    raw_spin_unlock_irqrestore(&x->wait.lock, flags);
}

/**
 * wait_for_completion_io_timeout: - waits for completion of a task (w/timeout)
 * @x:  holds the state of this particular completion
 * @timeout:  timeout value in jiffies
 *
 * This waits for either a completion of a specific task to be signaled or for a
 * specified timeout to expire. The timeout is in jiffies. It is not
 * interruptible. The caller is accounted as waiting for IO (which traditionally
 * means blkio only).
 *
 * Return: 0 if timed out, and positive (at least 1, or number of jiffies left
 * till timeout) if completed.
 */
unsigned long __sched
wait_for_completion_io_timeout(struct completion *x, unsigned long timeout)
{
    return wait_for_common_io(x, timeout, TASK_UNINTERRUPTIBLE);
}

/*
 * Generic wait-for-completion handler;
 *
 * It differs from semaphores in that their default case is the opposite,
 * wait_for_completion default blocks whereas semaphore default non-block. The
 * interface also makes it easy to 'complete' multiple waiting threads,
 * something which isn't entirely natural for semaphores.
 *
 * But more importantly, the primitive documents the usage. Semaphores would
 * typically be used for exclusion which gives rise to priority inversion.
 * Waiting for completion is a typically sync point, but not an exclusion point.
 */

static void complete_with_flags(struct completion *x, int wake_flags)
{
    unsigned long flags;

    raw_spin_lock_irqsave(&x->wait.lock, flags);

    if (x->done != UINT_MAX)
        x->done++;
    swake_up_locked(&x->wait, wake_flags);
    raw_spin_unlock_irqrestore(&x->wait.lock, flags);
}

/**
 * complete: - signals a single thread waiting on this completion
 * @x:  holds the state of this particular completion
 *
 * This will wake up a single thread waiting on this completion. Threads will be
 * awakened in the same order in which they were queued.
 *
 * See also complete_all(), wait_for_completion() and related routines.
 *
 * If this function wakes up a task, it executes a full memory barrier before
 * accessing the task state.
 */
void complete(struct completion *x)
{
    complete_with_flags(x, 0);
}
