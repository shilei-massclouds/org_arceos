#include <linux/blk-mq.h>
#include <linux/crash_dump.h>
#include <linux/kmemleak.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-pm.h"
#include "blk-stat.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"

#include "../adaptor.h"

static int blk_mq_init_request(struct blk_mq_tag_set *set, struct request *rq,
                   unsigned int hctx_idx, int node)
{
    int ret;

    if (set->ops->init_request) {
        ret = set->ops->init_request(set, rq, hctx_idx, node);
        if (ret)
            return ret;
    }

    WRITE_ONCE(rq->state, MQ_RQ_IDLE);
    return 0;
}

static void blk_mq_update_queue_map(struct blk_mq_tag_set *set)
{
    /*
     * blk_mq_map_queues() and multiple .map_queues() implementations
     * expect that set->map[HCTX_TYPE_DEFAULT].nr_queues is set to the
     * number of hardware queues.
     */
    if (set->nr_maps == 1)
        set->map[HCTX_TYPE_DEFAULT].nr_queues = set->nr_hw_queues;

    if (set->ops->map_queues) {
        int i;

        /*
         * transport .map_queues is usually done in the following
         * way:
         *
         * for (queue = 0; queue < set->nr_hw_queues; queue++) {
         *  mask = get_cpu_mask(queue)
         *  for_each_cpu(cpu, mask)
         *      set->map[x].mq_map[cpu] = queue;
         * }
         *
         * When we need to remap, the table has to be cleared for
         * killing stale mapping since one CPU may not be mapped
         * to any hw queue.
         */
        for (i = 0; i < set->nr_maps; i++)
            blk_mq_clear_mq_map(&set->map[i]);

        set->ops->map_queues(set);
    } else {
        BUG_ON(set->nr_maps > 1);
        blk_mq_map_queues(&set->map[HCTX_TYPE_DEFAULT]);
    }
}

static enum hctx_type hctx_idx_to_type(struct blk_mq_tag_set *set,
        unsigned int hctx_idx)
{
    int i;

    for (i = 0; i < set->nr_maps; i++) {
        unsigned int start = set->map[i].queue_offset;
        unsigned int end = start + set->map[i].nr_queues;

        if (hctx_idx >= start && hctx_idx < end)
            break;
    }

    if (i >= set->nr_maps)
        i = HCTX_TYPE_DEFAULT;

    return i;
}

static int blk_mq_get_hctx_node(struct blk_mq_tag_set *set,
        unsigned int hctx_idx)
{
    enum hctx_type type = hctx_idx_to_type(set, hctx_idx);

    return blk_mq_hw_queue_to_node(&set->map[type], hctx_idx);
}

static struct blk_mq_tags *blk_mq_alloc_rq_map(struct blk_mq_tag_set *set,
                           unsigned int hctx_idx,
                           unsigned int nr_tags,
                           unsigned int reserved_tags)
{
    int node = blk_mq_get_hctx_node(set, hctx_idx);
    struct blk_mq_tags *tags;

    if (node == NUMA_NO_NODE)
        node = set->numa_node;

    tags = blk_mq_init_tags(nr_tags, reserved_tags, node,
                BLK_MQ_FLAG_TO_ALLOC_POLICY(set->flags));
    if (!tags)
        return NULL;

    tags->rqs = kcalloc_node(nr_tags, sizeof(struct request *),
                 GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
                 node);
    if (!tags->rqs)
        goto err_free_tags;

    tags->static_rqs = kcalloc_node(nr_tags, sizeof(struct request *),
                    GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
                    node);
    if (!tags->static_rqs)
        goto err_free_rqs;

    return tags;

err_free_rqs:
    kfree(tags->rqs);
err_free_tags:
    blk_mq_free_tags(tags);
    return NULL;
}

static size_t order_to_size(unsigned int order)
{
    return (size_t)PAGE_SIZE << order;
}

static int blk_mq_alloc_rqs(struct blk_mq_tag_set *set,
                struct blk_mq_tags *tags,
                unsigned int hctx_idx, unsigned int depth)
{
    unsigned int i, j, entries_per_page, max_order = 4;
    int node = blk_mq_get_hctx_node(set, hctx_idx);
    size_t rq_size, left;

    if (node == NUMA_NO_NODE)
        node = set->numa_node;

    INIT_LIST_HEAD(&tags->page_list);

    /*
     * rq_size is the size of the request plus driver payload, rounded
     * to the cacheline size
     */
    rq_size = round_up(sizeof(struct request) + set->cmd_size,
                cache_line_size());
    left = rq_size * depth;

    for (i = 0; i < depth; ) {
        int this_order = max_order;
        struct page *page;
        int to_do;
        void *p;

        while (this_order && left < order_to_size(this_order - 1))
            this_order--;

        do {
            page = alloc_pages_node(node,
                GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY | __GFP_ZERO,
                this_order);
            if (page)
                break;
            if (!this_order--)
                break;
            if (order_to_size(this_order) < rq_size)
                break;
        } while (1);

        if (!page)
            goto fail;

        page->private = this_order;
        list_add_tail(&page->lru, &tags->page_list);

        p = page_address(page);
        /*
         * Allow kmemleak to scan these pages as they contain pointers
         * to additional allocations like via ops->init_request().
         */
        kmemleak_alloc(p, order_to_size(this_order), 1, GFP_NOIO);
        entries_per_page = order_to_size(this_order) / rq_size;
        to_do = min(entries_per_page, depth - i);
        left -= to_do * rq_size;
        for (j = 0; j < to_do; j++) {
            struct request *rq = p;

            tags->static_rqs[i] = rq;
            if (blk_mq_init_request(set, rq, hctx_idx, node)) {
                tags->static_rqs[i] = NULL;
                goto fail;
            }

            p += rq_size;
            i++;
        }
    }
    return 0;

fail:
    blk_mq_free_rqs(set, tags, hctx_idx);
    return -ENOMEM;
}

struct blk_mq_tags *blk_mq_alloc_map_and_rqs(struct blk_mq_tag_set *set,
                         unsigned int hctx_idx,
                         unsigned int depth)
{
    struct blk_mq_tags *tags;
    int ret;

    tags = blk_mq_alloc_rq_map(set, hctx_idx, depth, set->reserved_tags);
    if (!tags)
        return NULL;

    ret = blk_mq_alloc_rqs(set, tags, hctx_idx, depth);
    if (ret) {
        blk_mq_free_rq_map(tags);
        return NULL;
    }

    return tags;
}

static void __blk_mq_free_map_and_rqs(struct blk_mq_tag_set *set,
                      unsigned int hctx_idx)
{
    if (!blk_mq_is_shared_tags(set->flags))
        blk_mq_free_map_and_rqs(set, set->tags[hctx_idx], hctx_idx);

    set->tags[hctx_idx] = NULL;
}

static bool __blk_mq_alloc_map_and_rqs(struct blk_mq_tag_set *set,
                       int hctx_idx)
{
    if (blk_mq_is_shared_tags(set->flags)) {
        set->tags[hctx_idx] = set->shared_tags;

        return true;
    }

    set->tags[hctx_idx] = blk_mq_alloc_map_and_rqs(set, hctx_idx,
                               set->queue_depth);

    return set->tags[hctx_idx];
}

static int __blk_mq_alloc_rq_maps(struct blk_mq_tag_set *set)
{
    int i;

    if (blk_mq_is_shared_tags(set->flags)) {
        set->shared_tags = blk_mq_alloc_map_and_rqs(set,
                        BLK_MQ_NO_HCTX_IDX,
                        set->queue_depth);
        if (!set->shared_tags)
            return -ENOMEM;
    }

    for (i = 0; i < set->nr_hw_queues; i++) {
        if (!__blk_mq_alloc_map_and_rqs(set, i))
            goto out_unwind;
        cond_resched();
    }

    return 0;

out_unwind:
    while (--i >= 0)
        __blk_mq_free_map_and_rqs(set, i);

    if (blk_mq_is_shared_tags(set->flags)) {
        blk_mq_free_map_and_rqs(set, set->shared_tags,
                    BLK_MQ_NO_HCTX_IDX);
    }

    return -ENOMEM;
}

/*
 * Allocate the request maps associated with this tag_set. Note that this
 * may reduce the depth asked for, if memory is tight. set->queue_depth
 * will be updated to reflect the allocated depth.
 */
static int blk_mq_alloc_set_map_and_rqs(struct blk_mq_tag_set *set)
{
    unsigned int depth;
    int err;

    depth = set->queue_depth;
    do {
        err = __blk_mq_alloc_rq_maps(set);
        if (!err)
            break;

        set->queue_depth >>= 1;
        if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN) {
            err = -ENOMEM;
            break;
        }
    } while (set->queue_depth);

    if (!set->queue_depth || err) {
        pr_err("blk-mq: failed to allocate request map\n");
        return -ENOMEM;
    }

    if (depth != set->queue_depth)
        pr_info("blk-mq: reduced tag depth (%u -> %u)\n",
                        depth, set->queue_depth);

    return 0;
}

/*
 * Alloc a tag set to be associated with one or more request queues.
 * May fail with EINVAL for various error conditions. May adjust the
 * requested depth down, if it's too large. In that case, the set
 * value will be stored in set->queue_depth.
 */
int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set)
{
    int i, ret;

    BUILD_BUG_ON(BLK_MQ_MAX_DEPTH > 1 << BLK_MQ_UNIQUE_TAG_BITS);

    if (!set->nr_hw_queues)
        return -EINVAL;
    if (!set->queue_depth)
        return -EINVAL;
    if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN)
        return -EINVAL;

    if (!set->ops->queue_rq)
        return -EINVAL;

    if (!set->ops->get_budget ^ !set->ops->put_budget)
        return -EINVAL;

    if (set->queue_depth > BLK_MQ_MAX_DEPTH) {
        pr_info("blk-mq: reduced tag depth to %u\n",
            BLK_MQ_MAX_DEPTH);
        set->queue_depth = BLK_MQ_MAX_DEPTH;
    }

    if (!set->nr_maps)
        set->nr_maps = 1;
    else if (set->nr_maps > HCTX_MAX_TYPES)
        return -EINVAL;

    /*
     * If a crashdump is active, then we are potentially in a very
     * memory constrained environment. Limit us to  64 tags to prevent
     * using too much memory.
     */
    if (is_kdump_kernel())
        set->queue_depth = min(64U, set->queue_depth);

    /*
     * There is no use for more h/w queues than cpus if we just have
     * a single map
     */
    if (set->nr_maps == 1 && set->nr_hw_queues > nr_cpu_ids)
        set->nr_hw_queues = nr_cpu_ids;

    if (set->flags & BLK_MQ_F_BLOCKING) {
        set->srcu = kmalloc(sizeof(*set->srcu), GFP_KERNEL);
        if (!set->srcu)
            return -ENOMEM;
        ret = init_srcu_struct(set->srcu);
        if (ret)
            goto out_free_srcu;
    }

    ret = -ENOMEM;
    set->tags = kcalloc_node(set->nr_hw_queues,
                 sizeof(struct blk_mq_tags *), GFP_KERNEL,
                 set->numa_node);
    if (!set->tags)
        goto out_cleanup_srcu;

    for (i = 0; i < set->nr_maps; i++) {
        set->map[i].mq_map = kcalloc_node(nr_cpu_ids,
                          sizeof(set->map[i].mq_map[0]),
                          GFP_KERNEL, set->numa_node);
        if (!set->map[i].mq_map)
            goto out_free_mq_map;
        set->map[i].nr_queues = set->nr_hw_queues;
    }

    blk_mq_update_queue_map(set);

    ret = blk_mq_alloc_set_map_and_rqs(set);
    if (ret)
        goto out_free_mq_map;

    mutex_init(&set->tag_list_lock);
    INIT_LIST_HEAD(&set->tag_list);

    return 0;

out_free_mq_map:
    for (i = 0; i < set->nr_maps; i++) {
        kfree(set->map[i].mq_map);
        set->map[i].mq_map = NULL;
    }
    kfree(set->tags);
    set->tags = NULL;
out_cleanup_srcu:
    if (set->flags & BLK_MQ_F_BLOCKING)
        cleanup_srcu_struct(set->srcu);
out_free_srcu:
    if (set->flags & BLK_MQ_F_BLOCKING)
        kfree(set->srcu);
    return ret;
}
