#include <linux/kernel.h>
#include <linux/rculist.h>

#include "blk-stat.h"
#include "blk-mq.h"
#include "blk.h"

struct blk_queue_stats {
    struct list_head callbacks;
    spinlock_t lock;
    int accounting;
};

struct blk_queue_stats *blk_alloc_queue_stats(void)
{
    struct blk_queue_stats *stats;

    stats = kmalloc(sizeof(*stats), GFP_KERNEL);
    if (!stats)
        return NULL;

    INIT_LIST_HEAD(&stats->callbacks);
    spin_lock_init(&stats->lock);
    stats->accounting = 0;

    return stats;
}

void blk_free_queue_stats(struct blk_queue_stats *stats)
{
    if (!stats)
        return;

    WARN_ON(!list_empty(&stats->callbacks));

    kfree(stats);
}

void blk_stat_add(struct request *rq, u64 now)
{
    pr_err("%s: No impl.", __func__);
}
