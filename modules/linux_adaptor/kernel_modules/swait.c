#include <linux/swait.h>

#include "booter.h"

void __init_swait_queue_head(struct swait_queue_head *q, const char *name,
                 struct lock_class_key *key)
{
    raw_spin_lock_init(&q->lock);
    lockdep_set_class_and_name(&q->lock, key, name);
    INIT_LIST_HEAD(&q->task_list);
}
