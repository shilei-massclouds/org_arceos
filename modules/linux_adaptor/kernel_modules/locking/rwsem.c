#include <linux/rwsem.h>
#include <linux/sched/debug.h>

#include "../adaptor.h"

/*
 * Initialize an rwsem:
 */
void __init_rwsem(struct rw_semaphore *sem, const char *name,
          struct lock_class_key *key)
{
    pr_err("%s: No impl.", __func__);
}

/*
 * lock for writing
 */
void __sched down_write(struct rw_semaphore *sem)
{
    pr_err("%s: No impl.", __func__);
    /*
    might_sleep();
    rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);
    LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
    */
}

/*
 * release a write lock
 */
void up_write(struct rw_semaphore *sem)
{
    pr_err("%s: No impl.", __func__);
#if 0
    rwsem_release(&sem->dep_map, _RET_IP_);
    __up_write(sem);
#endif
}
