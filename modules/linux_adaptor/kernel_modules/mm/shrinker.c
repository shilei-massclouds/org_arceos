#include <linux/memcontrol.h>
#include <linux/rwsem.h>
#include <linux/shrinker.h>
#include <linux/rculist.h>
#include <trace/events/vmscan.h>

#include "internal.h"
#include "../adaptor.h"

LIST_HEAD(shrinker_list);
DEFINE_MUTEX(shrinker_mutex);

struct shrinker *shrinker_alloc(unsigned int flags, const char *fmt, ...)
{
    struct shrinker *shrinker;
    unsigned int size;
    va_list ap;
    int err;

    shrinker = kzalloc(sizeof(struct shrinker), GFP_KERNEL);
    if (!shrinker)
        return NULL;

    pr_notice("%s: No impl.", __func__);
    return shrinker;
}

void set_shrinker_bit(struct mem_cgroup *memcg, int nid, int shrinker_id)
{
    pr_notice("%s: No impl.", __func__);
}

void shrinker_register(struct shrinker *shrinker)
{
    if (unlikely(!(shrinker->flags & SHRINKER_ALLOCATED))) {
        pr_warn("Must use shrinker_alloc() to dynamically allocate the shrinker");
        return;
    }

    mutex_lock(&shrinker_mutex);
    list_add_tail_rcu(&shrinker->list, &shrinker_list);
    shrinker->flags |= SHRINKER_REGISTERED;
    shrinker_debugfs_add(shrinker);
    mutex_unlock(&shrinker_mutex);

    init_completion(&shrinker->done);
    /*
     * Now the shrinker is fully set up, take the first reference to it to
     * indicate that lookup operations are now allowed to use it via
     * shrinker_try_get().
     */
    refcount_set(&shrinker->refcount, 1);
}

void shrinker_free(struct shrinker *shrinker)
{
    struct dentry *debugfs_entry = NULL;
    int debugfs_id;

    if (!shrinker)
        return;

    pr_notice("%s: No impl.", __func__);
}
