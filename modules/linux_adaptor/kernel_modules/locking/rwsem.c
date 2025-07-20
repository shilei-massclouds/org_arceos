#include <linux/rwsem.h>

#include "../adaptor.h"

/*
 * Initialize an rwsem:
 */
void __init_rwsem(struct rw_semaphore *sem, const char *name,
          struct lock_class_key *key)
{
    pr_err("%s: No impl.", __func__);
}
