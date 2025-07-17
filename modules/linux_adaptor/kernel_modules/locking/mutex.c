#include <linux/mutex.h>
#include <linux/sched/debug.h>

#include "../adaptor.h"

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
