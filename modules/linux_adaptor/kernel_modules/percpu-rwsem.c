#include <linux/percpu-rwsem.h>

#include "booter.h"

int __percpu_init_rwsem(struct percpu_rw_semaphore *sem,
            const char *name, struct lock_class_key *key)
{
    log_debug("%s: ===> WARN: impl it.\n", __func__);

    sem->read_count = alloc_percpu(int);
    if (unlikely(!sem->read_count))
        return -ENOMEM;

    rcu_sync_init(&sem->rss);
    rcuwait_init(&sem->writer);
    init_waitqueue_head(&sem->waiters);
    atomic_set(&sem->block, 0);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
    debug_check_no_locks_freed((void *)sem, sizeof(*sem));
    lockdep_init_map(&sem->dep_map, name, key, 0);
#endif
    return 0;
}
