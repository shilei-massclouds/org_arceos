#include <linux/swait.h>
#include <linux/sched.h>
#include <linux/cpuset.h>

#include "sched.h"

void __init_swait_queue_head(struct swait_queue_head *q, const char *name,
                 struct lock_class_key *key)
{
    raw_spin_lock_init(&q->lock);
    lockdep_set_class_and_name(&q->lock, key, name);
    INIT_LIST_HEAD(&q->task_list);
}

/*
 * Wake up all waiters. This is an interface which is solely exposed for
 * completions and not for general usage.
 *
 * It is intentionally different from swake_up_all() to allow usage from
 * hard interrupt context and interrupt disabled regions.
 */
void swake_up_all_locked(struct swait_queue_head *q)
{
    while (!list_empty(&q->task_list))
        swake_up_locked(q, 0);
}

/*
 * The thing about the wake_up_state() return value; I think we can ignore it.
 *
 * If for some reason it would return 0, that means the previously waiting
 * task is already running, so it will observe condition true (or has already).
 */
void swake_up_locked(struct swait_queue_head *q, int wake_flags)
{
    struct swait_queue *curr;

    if (list_empty(&q->task_list))
        return;

    curr = list_first_entry(&q->task_list, typeof(*curr), task_list);
    try_to_wake_up(curr->task, TASK_NORMAL, wake_flags);
    list_del_init(&curr->task_list);
}
