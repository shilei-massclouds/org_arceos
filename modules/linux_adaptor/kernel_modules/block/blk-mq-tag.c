#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/delay.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"

static int bt_alloc(struct sbitmap_queue *bt, unsigned int depth,
            bool round_robin, int node)
{
    return sbitmap_queue_init_node(bt, depth, -1, round_robin, GFP_KERNEL,
                       node);
}

int blk_mq_init_bitmaps(struct sbitmap_queue *bitmap_tags,
            struct sbitmap_queue *breserved_tags,
            unsigned int queue_depth, unsigned int reserved,
            int node, int alloc_policy)
{
    unsigned int depth = queue_depth - reserved;
    bool round_robin = alloc_policy == BLK_TAG_ALLOC_RR;

    if (bt_alloc(bitmap_tags, depth, round_robin, node))
        return -ENOMEM;
    if (bt_alloc(breserved_tags, reserved, round_robin, node))
        goto free_bitmap_tags;

    return 0;

free_bitmap_tags:
    sbitmap_queue_free(bitmap_tags);
    return -ENOMEM;
}

struct blk_mq_tags *blk_mq_init_tags(unsigned int total_tags,
                     unsigned int reserved_tags,
                     int node, int alloc_policy)
{
    struct blk_mq_tags *tags;

    if (total_tags > BLK_MQ_TAG_MAX) {
        pr_err("blk-mq: tag depth too large\n");
        return NULL;
    }

    tags = kzalloc_node(sizeof(*tags), GFP_KERNEL, node);
    if (!tags)
        return NULL;

    tags->nr_tags = total_tags;
    tags->nr_reserved_tags = reserved_tags;
    spin_lock_init(&tags->lock);

    if (blk_mq_init_bitmaps(&tags->bitmap_tags, &tags->breserved_tags,
                total_tags, reserved_tags, node,
                alloc_policy) < 0) {
        kfree(tags);
        return NULL;
    }
    return tags;
}

void blk_mq_free_tags(struct blk_mq_tags *tags)
{
    sbitmap_queue_free(&tags->bitmap_tags);
    sbitmap_queue_free(&tags->breserved_tags);
    kfree(tags);
}
