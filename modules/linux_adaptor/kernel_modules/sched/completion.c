#include <linux/completion.h>
#include <linux/sched.h>
#include <linux/cpuset.h>

#include "sched.h"

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
