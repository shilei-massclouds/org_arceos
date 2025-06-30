#include <linux/wait.h>

#include "booter.h"

void __init_waitqueue_head(struct wait_queue_head *wq_head, const char *name, struct lock_class_key *key)
{
    log_debug("%s: No impl.", __func__);
}

void init_wait_entry(struct wait_queue_entry *wq_entry, int flags)
{
    wq_entry->flags = flags;
    wq_entry->private = current;
    wq_entry->func = autoremove_wake_function;
    INIT_LIST_HEAD(&wq_entry->entry);
}

long prepare_to_wait_event(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state)
{
    log_error("%s: No impl.", __func__);

    {
        static int i = 0;
        if (i++ > 3) {
            booter_panic("");
        }
    }

    return 0;
}

/**
 * __wake_up - wake up threads blocked on a waitqueue.
 * @wq_head: the waitqueue
 * @mode: which threads
 * @nr_exclusive: how many wake-one or wake-many threads to wake up
 * @key: is directly passed to the wakeup function
 *
 * If this function wakes up a task, it executes a full memory barrier before
 * accessing the task state.
 */
void __wake_up(struct wait_queue_head *wq_head, unsigned int mode,
            int nr_exclusive, void *key)
{
    log_error("%s: No impl.", __func__);
    //__wake_up_common_lock(wq_head, mode, nr_exclusive, 0, key);
}
