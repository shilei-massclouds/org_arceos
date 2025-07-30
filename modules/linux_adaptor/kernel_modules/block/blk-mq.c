#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/kmemleak.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/llist.h>
#include <linux/cpu.h>
#include <linux/cache.h>
#include <linux/sched/topology.h>
#include <linux/sched/signal.h>
#include <linux/delay.h>
#include <linux/crash_dump.h>
#include <linux/prefetch.h>
#include <linux/blk-crypto.h>
#include <linux/part_stat.h>
#include <linux/sched/isolation.h>

#include <trace/events/block.h>

#include <linux/t10-pi.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-pm.h"
#include "blk-stat.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"

#include "../adaptor.h"

static DEFINE_MUTEX(blk_mq_cpuhp_lock);

static void __blk_mq_requeue_request(struct request *rq)
{
    struct request_queue *q = rq->q;

    blk_mq_put_driver_tag(rq);

    trace_block_rq_requeue(rq);
    rq_qos_requeue(q, rq);

    if (blk_mq_request_started(rq)) {
        WRITE_ONCE(rq->state, MQ_RQ_IDLE);
        rq->rq_flags &= ~RQF_TIMED_OUT;
    }
}

static void blk_mq_handle_dev_resource(struct request *rq,
                       struct list_head *list)
{
    list_add(&rq->queuelist, list);
    __blk_mq_requeue_request(rq);
}

enum prep_dispatch {
    PREP_DISPATCH_OK,
    PREP_DISPATCH_NO_TAG,
    PREP_DISPATCH_NO_BUDGET,
};

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

static void __blk_mq_remove_cpuhp(struct blk_mq_hw_ctx *hctx)
{
    PANIC("");
}

static void __blk_mq_add_cpuhp(struct blk_mq_hw_ctx *hctx)
{
    lockdep_assert_held(&blk_mq_cpuhp_lock);

    if (!(hctx->flags & BLK_MQ_F_STACKING) &&
        hlist_unhashed(&hctx->cpuhp_online))
        cpuhp_state_add_instance_nocalls(CPUHP_AP_BLK_MQ_ONLINE,
                &hctx->cpuhp_online);

    if (hlist_unhashed(&hctx->cpuhp_dead))
        cpuhp_state_add_instance_nocalls(CPUHP_BLK_MQ_DEAD,
                &hctx->cpuhp_dead);
}

static void __blk_mq_remove_cpuhp_list(struct list_head *head)
{
    struct blk_mq_hw_ctx *hctx;

    lockdep_assert_held(&blk_mq_cpuhp_lock);

    list_for_each_entry(hctx, head, hctx_list)
        __blk_mq_remove_cpuhp(hctx);
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

void blk_mq_free_plug_rqs(struct blk_plug *plug)
{
    struct request *rq;

    while ((rq = rq_list_pop(&plug->cached_rqs)) != NULL)
        blk_mq_free_request(rq);
}

struct gendisk *__blk_mq_alloc_disk(struct blk_mq_tag_set *set,
        struct queue_limits *lim, void *queuedata,
        struct lock_class_key *lkclass)
{
    struct request_queue *q;
    struct gendisk *disk;

    q = blk_mq_alloc_queue(set, lim, queuedata);
    if (IS_ERR(q))
        return ERR_CAST(q);

    disk = __alloc_disk_node(q, set->numa_node, lkclass);
    if (!disk) {
        blk_mq_destroy_queue(q);
        blk_put_queue(q);
        return ERR_PTR(-ENOMEM);
    }
    set_bit(GD_OWNS_QUEUE, &disk->state);
    return disk;
}

struct request_queue *blk_mq_alloc_queue(struct blk_mq_tag_set *set,
        struct queue_limits *lim, void *queuedata)
{
    struct queue_limits default_lim = { };
    struct request_queue *q;
    int ret;

    if (!lim)
        lim = &default_lim;
    lim->features |= BLK_FEAT_IO_STAT | BLK_FEAT_NOWAIT;
    if (set->nr_maps > HCTX_TYPE_POLL)
        lim->features |= BLK_FEAT_POLL;

    q = blk_alloc_queue(lim, set->numa_node);
    if (IS_ERR(q))
        return q;
    q->queuedata = queuedata;
    ret = blk_mq_init_allocated_queue(set, q);
    if (ret) {
        blk_put_queue(q);
        return ERR_PTR(ret);
    }
    return q;
}

/* All allocations will be freed in release handler of q->mq_kobj */
static int blk_mq_alloc_ctxs(struct request_queue *q)
{
    struct blk_mq_ctxs *ctxs;
    int cpu;

    ctxs = kzalloc(sizeof(*ctxs), GFP_KERNEL);
    if (!ctxs)
        return -ENOMEM;

    ctxs->queue_ctx = alloc_percpu(struct blk_mq_ctx);
    if (!ctxs->queue_ctx)
        goto fail;

    for_each_possible_cpu(cpu) {
        struct blk_mq_ctx *ctx = per_cpu_ptr(ctxs->queue_ctx, cpu);
        ctx->ctxs = ctxs;
    }

    q->mq_kobj = &ctxs->kobj;
    q->queue_ctx = ctxs->queue_ctx;

    return 0;
 fail:
    kfree(ctxs);
    return -ENOMEM;
}

static void blk_mq_init_cpu_queues(struct request_queue *q,
                   unsigned int nr_hw_queues)
{
    struct blk_mq_tag_set *set = q->tag_set;
    unsigned int i, j;

    for_each_possible_cpu(i) {
        struct blk_mq_ctx *__ctx = per_cpu_ptr(q->queue_ctx, i);
        struct blk_mq_hw_ctx *hctx;
        int k;

        __ctx->cpu = i;
        spin_lock_init(&__ctx->lock);
        for (k = HCTX_TYPE_DEFAULT; k < HCTX_MAX_TYPES; k++)
            INIT_LIST_HEAD(&__ctx->rq_lists[k]);

        __ctx->queue = q;

        /*
         * Set local node, IFF we have more than one hw queue. If
         * not, we remain on the home node of the device
         */
        for (j = 0; j < set->nr_maps; j++) {
            hctx = blk_mq_map_queue_type(q, j, i);
            if (nr_hw_queues > 1 && hctx->numa_node == NUMA_NO_NODE)
                hctx->numa_node = cpu_to_node(i);
        }
    }
}

static void blk_mq_update_tag_set_shared(struct blk_mq_tag_set *set,
                     bool shared)
{
    PANIC("");
}

/*
 * Caller needs to ensure that we're either frozen/quiesced, or that
 * the queue isn't live yet.
 */
static void queue_set_hctx_shared(struct request_queue *q, bool shared)
{
    PANIC("");
}

static void blk_mq_add_queue_tag_set(struct blk_mq_tag_set *set,
                     struct request_queue *q)
{
    mutex_lock(&set->tag_list_lock);

    /*
     * Check to see if we're transitioning to shared (from 1 to 2 queues).
     */
    if (!list_empty(&set->tag_list) &&
        !(set->flags & BLK_MQ_F_TAG_QUEUE_SHARED)) {
        set->flags |= BLK_MQ_F_TAG_QUEUE_SHARED;
        /* update existing queue */
        blk_mq_update_tag_set_shared(set, true);
    }
    if (set->flags & BLK_MQ_F_TAG_QUEUE_SHARED)
        queue_set_hctx_shared(q, true);
    list_add_tail(&q->tag_set_list, &set->tag_list);

    mutex_unlock(&set->tag_list_lock);
}

static inline int blk_mq_first_mapped_cpu(struct blk_mq_hw_ctx *hctx)
{
    int cpu = cpumask_first_and(hctx->cpumask, cpu_online_mask);

    if (cpu >= nr_cpu_ids)
        cpu = cpumask_first(hctx->cpumask);
    return cpu;
}

static void blk_mq_map_swqueue(struct request_queue *q)
{
    unsigned int j, hctx_idx;
    unsigned long i;
    struct blk_mq_hw_ctx *hctx;
    struct blk_mq_ctx *ctx;
    struct blk_mq_tag_set *set = q->tag_set;

    queue_for_each_hw_ctx(q, hctx, i) {
        cpumask_clear(hctx->cpumask);
        hctx->nr_ctx = 0;
        hctx->dispatch_from = NULL;
    }

    /*
     * Map software to hardware queues.
     *
     * If the cpu isn't present, the cpu is mapped to first hctx.
     */
    for_each_possible_cpu(i) {

        ctx = per_cpu_ptr(q->queue_ctx, i);
        for (j = 0; j < set->nr_maps; j++) {
            if (!set->map[j].nr_queues) {
                ctx->hctxs[j] = blk_mq_map_queue_type(q,
                        HCTX_TYPE_DEFAULT, i);
                continue;
            }
            hctx_idx = set->map[j].mq_map[i];
            /* unmapped hw queue can be remapped after CPU topo changed */
            if (!set->tags[hctx_idx] &&
                !__blk_mq_alloc_map_and_rqs(set, hctx_idx)) {
                /*
                 * If tags initialization fail for some hctx,
                 * that hctx won't be brought online.  In this
                 * case, remap the current ctx to hctx[0] which
                 * is guaranteed to always have tags allocated
                 */
                set->map[j].mq_map[i] = 0;
            }

            hctx = blk_mq_map_queue_type(q, j, i);
            ctx->hctxs[j] = hctx;
            /*
             * If the CPU is already set in the mask, then we've
             * mapped this one already. This can happen if
             * devices share queues across queue maps.
             */
            if (cpumask_test_cpu(i, hctx->cpumask))
                continue;

            cpumask_set_cpu(i, hctx->cpumask);
            hctx->type = j;
            ctx->index_hw[hctx->type] = hctx->nr_ctx;
            hctx->ctxs[hctx->nr_ctx++] = ctx;

            /*
             * If the nr_ctx type overflows, we have exceeded the
             * amount of sw queues we can support.
             */
            BUG_ON(!hctx->nr_ctx);
        }

        for (; j < HCTX_MAX_TYPES; j++)
            ctx->hctxs[j] = blk_mq_map_queue_type(q,
                    HCTX_TYPE_DEFAULT, i);
    }

    queue_for_each_hw_ctx(q, hctx, i) {
        int cpu;

        /*
         * If no software queues are mapped to this hardware queue,
         * disable it and free the request entries.
         */
        if (!hctx->nr_ctx) {
            /* Never unmap queue 0.  We need it as a
             * fallback in case of a new remap fails
             * allocation
             */
            if (i)
                __blk_mq_free_map_and_rqs(set, i);

            hctx->tags = NULL;
            continue;
        }

        hctx->tags = set->tags[i];
        WARN_ON(!hctx->tags);

        /*
         * Set the map size to the number of mapped software queues.
         * This is more accurate and more efficient than looping
         * over all possibly mapped software queues.
         */
        sbitmap_resize(&hctx->ctx_map, hctx->nr_ctx);

        /*
         * Rule out isolated CPUs from hctx->cpumask to avoid
         * running block kworker on isolated CPUs
         */
        for_each_cpu(cpu, hctx->cpumask) {
            if (cpu_is_isolated(cpu))
                cpumask_clear_cpu(cpu, hctx->cpumask);
        }

        /*
         * Initialize batch roundrobin counts
         */
        hctx->next_cpu = blk_mq_first_mapped_cpu(hctx);
        hctx->next_cpu_batch = BLK_MQ_CPU_WORK_BATCH;
    }
}

/* hctx->ctxs will be freed in queue's release handler */
static void blk_mq_exit_hctx(struct request_queue *q,
        struct blk_mq_tag_set *set,
        struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
    PANIC("");
}

static void blk_mq_run_work_fn(struct work_struct *work)
{
    PANIC("");
}

static int blk_mq_dispatch_wake(wait_queue_entry_t *wait, unsigned mode,
                int flags, void *key)
{
    PANIC("");
}

static struct blk_mq_hw_ctx *
blk_mq_alloc_hctx(struct request_queue *q, struct blk_mq_tag_set *set,
        int node)
{
    struct blk_mq_hw_ctx *hctx;
    gfp_t gfp = GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY;

    hctx = kzalloc_node(sizeof(struct blk_mq_hw_ctx), gfp, node);
    if (!hctx)
        goto fail_alloc_hctx;

    if (!zalloc_cpumask_var_node(&hctx->cpumask, gfp, node))
        goto free_hctx;

    atomic_set(&hctx->nr_active, 0);
    if (node == NUMA_NO_NODE)
        node = set->numa_node;
    hctx->numa_node = node;

    //INIT_DELAYED_WORK(&hctx->run_work, blk_mq_run_work_fn);
    spin_lock_init(&hctx->lock);
    INIT_LIST_HEAD(&hctx->dispatch);
    INIT_HLIST_NODE(&hctx->cpuhp_dead);
    INIT_HLIST_NODE(&hctx->cpuhp_online);
    hctx->queue = q;
    hctx->flags = set->flags & ~BLK_MQ_F_TAG_QUEUE_SHARED;

    INIT_LIST_HEAD(&hctx->hctx_list);

    /*
     * Allocate space for all possible cpus to avoid allocation at
     * runtime
     */
    hctx->ctxs = kmalloc_array_node(nr_cpu_ids, sizeof(void *),
            gfp, node);
    if (!hctx->ctxs)
        goto free_cpumask;

    if (sbitmap_init_node(&hctx->ctx_map, nr_cpu_ids, ilog2(8),
                gfp, node, false, false))
        goto free_ctxs;
    hctx->nr_ctx = 0;

    spin_lock_init(&hctx->dispatch_wait_lock);
    init_waitqueue_func_entry(&hctx->dispatch_wait, blk_mq_dispatch_wake);
    INIT_LIST_HEAD(&hctx->dispatch_wait.entry);

    hctx->fq = blk_alloc_flush_queue(hctx->numa_node, set->cmd_size, gfp);
    if (!hctx->fq)
        goto free_bitmap;

    blk_mq_hctx_kobj_init(hctx);

    return hctx;

 free_bitmap:
    sbitmap_free(&hctx->ctx_map);
 free_ctxs:
    kfree(hctx->ctxs);
 free_cpumask:
    free_cpumask_var(hctx->cpumask);
 free_hctx:
    kfree(hctx);
 fail_alloc_hctx:
    return NULL;
}

static int blk_mq_init_hctx(struct request_queue *q,
        struct blk_mq_tag_set *set,
        struct blk_mq_hw_ctx *hctx, unsigned hctx_idx)
{
    hctx->queue_num = hctx_idx;

    hctx->tags = set->tags[hctx_idx];

    if (set->ops->init_hctx &&
        set->ops->init_hctx(hctx, set->driver_data, hctx_idx))
        goto fail;

    if (blk_mq_init_request(set, hctx->fq->flush_rq, hctx_idx,
                hctx->numa_node))
        goto exit_hctx;

    if (xa_insert(&q->hctx_table, hctx_idx, hctx, GFP_KERNEL))
        goto exit_flush_rq;

    if (!(hctx->flags & BLK_MQ_F_STACKING))
        cpuhp_state_add_instance_nocalls(CPUHP_AP_BLK_MQ_ONLINE,
                &hctx->cpuhp_online);
    cpuhp_state_add_instance_nocalls(CPUHP_BLK_MQ_DEAD, &hctx->cpuhp_dead);

    return 0;

 exit_flush_rq:
    if (set->ops->exit_request)
        set->ops->exit_request(set, hctx->fq->flush_rq, hctx_idx);
 exit_hctx:
    if (set->ops->exit_hctx)
        set->ops->exit_hctx(hctx, hctx_idx);
 fail:
    return -1;
}

/*
 * Only hctx removed from cpuhp list can be reused
 */
static bool blk_mq_hctx_is_reusable(struct blk_mq_hw_ctx *hctx)
{
    return hlist_unhashed(&hctx->cpuhp_online) &&
        hlist_unhashed(&hctx->cpuhp_dead);
}

static struct blk_mq_hw_ctx *blk_mq_alloc_and_init_hctx(
        struct blk_mq_tag_set *set, struct request_queue *q,
        int hctx_idx, int node)
{
    struct blk_mq_hw_ctx *hctx = NULL, *tmp;

    /* reuse dead hctx first */
    spin_lock(&q->unused_hctx_lock);
    list_for_each_entry(tmp, &q->unused_hctx_list, hctx_list) {
        if (tmp->numa_node == node && blk_mq_hctx_is_reusable(tmp)) {
            hctx = tmp;
            break;
        }
    }
    if (hctx)
        list_del_init(&hctx->hctx_list);
    spin_unlock(&q->unused_hctx_lock);

    if (!hctx)
        hctx = blk_mq_alloc_hctx(q, set, node);
    if (!hctx)
        goto fail;

    if (blk_mq_init_hctx(q, set, hctx, hctx_idx))
        goto free_hctx;

    return hctx;

 free_hctx:
    kobject_put(&hctx->kobj);
 fail:
    return NULL;
}

/*
 * Unregister cpuhp callbacks from exited hw queues
 *
 * Safe to call if this `request_queue` is live
 */
static void blk_mq_remove_hw_queues_cpuhp(struct request_queue *q)
{
    LIST_HEAD(hctx_list);

    spin_lock(&q->unused_hctx_lock);
    list_splice_init(&q->unused_hctx_list, &hctx_list);
    spin_unlock(&q->unused_hctx_lock);

    mutex_lock(&blk_mq_cpuhp_lock);
    __blk_mq_remove_cpuhp_list(&hctx_list);
    mutex_unlock(&blk_mq_cpuhp_lock);

    spin_lock(&q->unused_hctx_lock);
    list_splice(&hctx_list, &q->unused_hctx_list);
    spin_unlock(&q->unused_hctx_lock);
}

/*
 * Register cpuhp callbacks from all hw queues
 *
 * Safe to call if this `request_queue` is live
 */
static void blk_mq_add_hw_queues_cpuhp(struct request_queue *q)
{
    struct blk_mq_hw_ctx *hctx;
    unsigned long i;

    mutex_lock(&blk_mq_cpuhp_lock);
    queue_for_each_hw_ctx(q, hctx, i)
        __blk_mq_add_cpuhp(hctx);
    mutex_unlock(&blk_mq_cpuhp_lock);
}

static void blk_mq_realloc_hw_ctxs(struct blk_mq_tag_set *set,
                        struct request_queue *q)
{
    struct blk_mq_hw_ctx *hctx;
    unsigned long i, j;

    /* protect against switching io scheduler  */
    mutex_lock(&q->sysfs_lock);
    for (i = 0; i < set->nr_hw_queues; i++) {
        int old_node;
        int node = blk_mq_get_hctx_node(set, i);
        struct blk_mq_hw_ctx *old_hctx = xa_load(&q->hctx_table, i);

        if (old_hctx) {
            old_node = old_hctx->numa_node;
            blk_mq_exit_hctx(q, set, old_hctx, i);
        }

        if (!blk_mq_alloc_and_init_hctx(set, q, i, node)) {
            if (!old_hctx)
                break;
            pr_warn("Allocate new hctx on node %d fails, fallback to previous one on node %d\n",
                    node, old_node);
            hctx = blk_mq_alloc_and_init_hctx(set, q, i, old_node);
            WARN_ON_ONCE(!hctx);
        }
    }
    /*
     * Increasing nr_hw_queues fails. Free the newly allocated
     * hctxs and keep the previous q->nr_hw_queues.
     */
    if (i != set->nr_hw_queues) {
        j = q->nr_hw_queues;
    } else {
        j = i;
        q->nr_hw_queues = set->nr_hw_queues;
    }

    xa_for_each_start(&q->hctx_table, j, hctx, j)
        blk_mq_exit_hctx(q, set, hctx, j);
    mutex_unlock(&q->sysfs_lock);

    /* unregister cpuhp callbacks for exited hctxs */
    blk_mq_remove_hw_queues_cpuhp(q);

    /* register cpuhp for new initialized hctxs */
    blk_mq_add_hw_queues_cpuhp(q);
}

/*
 * It is the actual release handler for mq, but we do it from
 * request queue's release handler for avoiding use-after-free
 * and headache because q->mq_kobj shouldn't have been introduced,
 * but we can't group ctx/kctx kobj without it.
 */
void blk_mq_release(struct request_queue *q)
{
    PANIC("");
}

/*
 * Mark this ctx as having pending work in this hardware queue
 */
static void blk_mq_hctx_mark_pending(struct blk_mq_hw_ctx *hctx,
                     struct blk_mq_ctx *ctx)
{
    const int bit = ctx->index_hw[hctx->type];

    if (!sbitmap_test_bit(&hctx->ctx_map, bit))
        sbitmap_set_bit(&hctx->ctx_map, bit);
}

/**
 * blk_mq_request_bypass_insert - Insert a request at dispatch list.
 * @rq: Pointer to request to be inserted.
 * @flags: BLK_MQ_INSERT_*
 *
 * Should only be used carefully, when the caller knows we want to
 * bypass a potential IO scheduler on the target device.
 */
static void blk_mq_request_bypass_insert(struct request *rq, blk_insert_t flags)
{
    struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

    spin_lock(&hctx->lock);
    if (flags & BLK_MQ_INSERT_AT_HEAD)
        list_add(&rq->queuelist, &hctx->dispatch);
    else
        list_add_tail(&rq->queuelist, &hctx->dispatch);
    spin_unlock(&hctx->lock);
}

static void blk_mq_insert_request(struct request *rq, blk_insert_t flags)
{
    struct request_queue *q = rq->q;
    struct blk_mq_ctx *ctx = rq->mq_ctx;
    struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

    if (blk_rq_is_passthrough(rq)) {
        /*
         * Passthrough request have to be added to hctx->dispatch
         * directly.  The device may be in a situation where it can't
         * handle FS request, and always returns BLK_STS_RESOURCE for
         * them, which gets them added to hctx->dispatch.
         *
         * If a passthrough request is required to unblock the queues,
         * and it is added to the scheduler queue, there is no chance to
         * dispatch it given we prioritize requests in hctx->dispatch.
         */
        blk_mq_request_bypass_insert(rq, flags);
    } else if (req_op(rq) == REQ_OP_FLUSH) {
        /*
         * Firstly normal IO request is inserted to scheduler queue or
         * sw queue, meantime we add flush request to dispatch queue(
         * hctx->dispatch) directly and there is at most one in-flight
         * flush request for each hw queue, so it doesn't matter to add
         * flush request to tail or front of the dispatch queue.
         *
         * Secondly in case of NCQ, flush request belongs to non-NCQ
         * command, and queueing it will fail when there is any
         * in-flight normal IO request(NCQ command). When adding flush
         * rq to the front of hctx->dispatch, it is easier to introduce
         * extra time to flush rq's latency because of S_SCHED_RESTART
         * compared with adding to the tail of dispatch queue, then
         * chance of flush merge is increased, and less flush requests
         * will be issued to controller. It is observed that ~10% time
         * is saved in blktests block/004 on disk attached to AHCI/NCQ
         * drive when adding flush rq to the front of hctx->dispatch.
         *
         * Simply queue flush rq to the front of hctx->dispatch so that
         * intensive flush workloads can benefit in case of NCQ HW.
         */
        blk_mq_request_bypass_insert(rq, BLK_MQ_INSERT_AT_HEAD);
    } else if (q->elevator) {
        LIST_HEAD(list);

        WARN_ON_ONCE(rq->tag != BLK_MQ_NO_TAG);

        list_add(&rq->queuelist, &list);
        q->elevator->type->ops.insert_requests(hctx, &list, flags);
    } else {
        trace_block_rq_insert(rq);

        spin_lock(&ctx->lock);
        if (flags & BLK_MQ_INSERT_AT_HEAD)
            list_add(&rq->queuelist, &ctx->rq_lists[hctx->type]);
        else
            list_add_tail(&rq->queuelist,
                      &ctx->rq_lists[hctx->type]);
        blk_mq_hctx_mark_pending(hctx, ctx);
        spin_unlock(&ctx->lock);
    }
}

static void blk_mq_requeue_work(struct work_struct *work)
{
    struct request_queue *q =
        container_of(work, struct request_queue, requeue_work.work);
    LIST_HEAD(rq_list);
    LIST_HEAD(flush_list);
    struct request *rq;

    spin_lock_irq(&q->requeue_lock);
    list_splice_init(&q->requeue_list, &rq_list);
    list_splice_init(&q->flush_list, &flush_list);
    spin_unlock_irq(&q->requeue_lock);

    while (!list_empty(&rq_list)) {
        rq = list_entry(rq_list.next, struct request, queuelist);
        /*
         * If RQF_DONTPREP ist set, the request has been started by the
         * driver already and might have driver-specific data allocated
         * already.  Insert it into the hctx dispatch list to avoid
         * block layer merges for the request.
         */
        if (rq->rq_flags & RQF_DONTPREP) {
            list_del_init(&rq->queuelist);
            blk_mq_request_bypass_insert(rq, 0);
        } else {
            list_del_init(&rq->queuelist);
            blk_mq_insert_request(rq, BLK_MQ_INSERT_AT_HEAD);
        }
        PANIC("LOOP");
    }

    while (!list_empty(&flush_list)) {
        rq = list_entry(flush_list.next, struct request, queuelist);
        list_del_init(&rq->queuelist);
        blk_mq_insert_request(rq, 0);
    }

    blk_mq_run_hw_queues(q, false);
}

/*
 * Return prefered queue to dispatch from (if any) for non-mq aware IO
 * scheduler.
 */
static struct blk_mq_hw_ctx *blk_mq_get_sq_hctx(struct request_queue *q)
{
    struct blk_mq_ctx *ctx = blk_mq_get_ctx(q);
    /*
     * If the IO scheduler does not respect hardware queues when
     * dispatching, we just don't bother with multiple HW queues and
     * dispatch from hctx for the current CPU since running multiple queues
     * just causes lock contention inside the scheduler and pointless cache
     * bouncing.
     */
    struct blk_mq_hw_ctx *hctx = ctx->hctxs[HCTX_TYPE_DEFAULT];

    if (!blk_mq_hctx_stopped(hctx))
        return hctx;
    return NULL;
}

/**
 * blk_mq_run_hw_queues - Run all hardware queues in a request queue.
 * @q: Pointer to the request queue to run.
 * @async: If we want to run the queue asynchronously.
 */
void blk_mq_run_hw_queues(struct request_queue *q, bool async)
{
    struct blk_mq_hw_ctx *hctx, *sq_hctx;
    unsigned long i;

    sq_hctx = NULL;
    if (blk_queue_sq_sched(q))
        sq_hctx = blk_mq_get_sq_hctx(q);
    queue_for_each_hw_ctx(q, hctx, i) {
        if (blk_mq_hctx_stopped(hctx))
            continue;
        /*
         * Dispatch from this hctx either if there's no hctx preferred
         * by IO scheduler or if it has requests that bypass the
         * scheduler.
         */
        if (!sq_hctx || sq_hctx == hctx ||
            !list_empty_careful(&hctx->dispatch))
            blk_mq_run_hw_queue(hctx, async);
    }
}

/*
 * Check if any of the ctx, dispatch list or elevator
 * have pending work in this hardware queue.
 */
static bool blk_mq_hctx_has_pending(struct blk_mq_hw_ctx *hctx)
{
    return !list_empty_careful(&hctx->dispatch) ||
        sbitmap_any_bit_set(&hctx->ctx_map) ||
            blk_mq_sched_has_work(hctx);
}

/*
 * It'd be great if the workqueue API had a way to pass
 * in a mask and had some smarts for more clever placement.
 * For now we just round-robin here, switching for every
 * BLK_MQ_CPU_WORK_BATCH queued items.
 */
static int blk_mq_hctx_next_cpu(struct blk_mq_hw_ctx *hctx)
{
    PANIC("");
}

static inline bool blk_mq_hw_queue_need_run(struct blk_mq_hw_ctx *hctx)
{
    bool need_run;

    /*
     * When queue is quiesced, we may be switching io scheduler, or
     * updating nr_hw_queues, or other things, and we can't run queue
     * any more, even blk_mq_hctx_has_pending() can't be called safely.
     *
     * And queue will be rerun in blk_mq_unquiesce_queue() if it is
     * quiesced.
     */
    __blk_mq_run_dispatch_ops(hctx->queue, false,
        need_run = !blk_queue_quiesced(hctx->queue) &&
        blk_mq_hctx_has_pending(hctx));
    return need_run;
}

/**
 * blk_mq_delay_run_hw_queues - Run all hardware queues asynchronously.
 * @q: Pointer to the request queue to run.
 * @msecs: Milliseconds of delay to wait before running the queues.
 */
void blk_mq_delay_run_hw_queues(struct request_queue *q, unsigned long msecs)
{
    struct blk_mq_hw_ctx *hctx, *sq_hctx;
    unsigned long i;

#if 0
    sq_hctx = NULL;
    if (blk_queue_sq_sched(q))
        sq_hctx = blk_mq_get_sq_hctx(q);
    queue_for_each_hw_ctx(q, hctx, i) {
        if (blk_mq_hctx_stopped(hctx))
            continue;
        /*
         * If there is already a run_work pending, leave the
         * pending delay untouched. Otherwise, a hctx can stall
         * if another hctx is re-delaying the other's work
         * before the work executes.
         */
        if (delayed_work_pending(&hctx->run_work))
            continue;
        /*
         * Dispatch from this hctx either if there's no hctx preferred
         * by IO scheduler or if it has requests that bypass the
         * scheduler.
         */
        if (!sq_hctx || sq_hctx == hctx ||
            !list_empty_careful(&hctx->dispatch))
            blk_mq_delay_run_hw_queue(hctx, msecs);
    }
#endif
    PANIC("");
}

/**
 * blk_mq_delay_run_hw_queue - Run a hardware queue asynchronously.
 * @hctx: Pointer to the hardware queue to run.
 * @msecs: Milliseconds of delay to wait before running the queue.
 *
 * Run a hardware queue asynchronously with a delay of @msecs.
 */
void blk_mq_delay_run_hw_queue(struct blk_mq_hw_ctx *hctx, unsigned long msecs)
{
    if (unlikely(blk_mq_hctx_stopped(hctx)))
        return;
    kblockd_mod_delayed_work_on(blk_mq_hctx_next_cpu(hctx), &hctx->run_work,
                    msecs_to_jiffies(msecs));
}

/**
 * blk_mq_run_hw_queue - Start to run a hardware queue.
 * @hctx: Pointer to the hardware queue to run.
 * @async: If we want to run the queue asynchronously.
 *
 * Check if the request queue is not in a quiesced state and if there are
 * pending requests to be sent. If this is true, run the queue to send requests
 * to hardware.
 */
void blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx, bool async)
{
    bool need_run;

    /*
     * We can't run the queue inline with interrupts disabled.
     */
    WARN_ON_ONCE(!async && in_interrupt());

    might_sleep_if(!async && hctx->flags & BLK_MQ_F_BLOCKING);

    need_run = blk_mq_hw_queue_need_run(hctx);
    if (!need_run) {
        unsigned long flags;

        /*
         * Synchronize with blk_mq_unquiesce_queue(), because we check
         * if hw queue is quiesced locklessly above, we need the use
         * ->queue_lock to make sure we see the up-to-date status to
         * not miss rerunning the hw queue.
         */
        spin_lock_irqsave(&hctx->queue->queue_lock, flags);
        need_run = blk_mq_hw_queue_need_run(hctx);
        spin_unlock_irqrestore(&hctx->queue->queue_lock, flags);

        if (!need_run)
            return;
    }

    if (async || !cpumask_test_cpu(raw_smp_processor_id(), hctx->cpumask)) {
        blk_mq_delay_run_hw_queue(hctx, 0);
        return;
    }

    blk_mq_run_dispatch_ops(hctx->queue,
                blk_mq_sched_dispatch_requests(hctx));
}

int blk_mq_init_allocated_queue(struct blk_mq_tag_set *set,
        struct request_queue *q)
{
    pr_err("%s: No impl.", __func__);

    /* mark the queue as mq asap */
    q->mq_ops = set->ops;

    /*
     * ->tag_set has to be setup before initialize hctx, which cpuphp
     * handler needs it for checking queue mapping
     */
    q->tag_set = set;

    if (blk_mq_alloc_ctxs(q))
        goto err_exit;

    /* init q->mq_kobj and sw queues' kobjects */
    //blk_mq_sysfs_init(q);

    INIT_LIST_HEAD(&q->unused_hctx_list);
    spin_lock_init(&q->unused_hctx_lock);

    xa_init(&q->hctx_table);

    blk_mq_realloc_hw_ctxs(set, q);
    if (!q->nr_hw_queues)
        goto err_hctxs;

#if 0
    INIT_WORK(&q->timeout_work, blk_mq_timeout_work);
    blk_queue_rq_timeout(q, set->timeout ? set->timeout : 30 * HZ);
#endif

    q->queue_flags |= QUEUE_FLAG_MQ_DEFAULT;

    INIT_DELAYED_WORK(&q->requeue_work, blk_mq_requeue_work);
    INIT_LIST_HEAD(&q->flush_list);
    INIT_LIST_HEAD(&q->requeue_list);
    spin_lock_init(&q->requeue_lock);

    q->nr_requests = set->queue_depth;

    blk_mq_init_cpu_queues(q, set->nr_hw_queues);
    blk_mq_add_queue_tag_set(set, q);
    blk_mq_map_swqueue(q);
    return 0;

err_hctxs:
    blk_mq_release(q);
err_exit:
    q->mq_ops = NULL;
    return -ENOMEM;
}

/*
 * Check if there is a suitable cached request and return it.
 */
static struct request *blk_mq_peek_cached_request(struct blk_plug *plug,
        struct request_queue *q, blk_opf_t opf)
{
    enum hctx_type type = blk_mq_get_hctx_type(opf);
    struct request *rq;

    if (!plug)
        return NULL;
    rq = rq_list_peek(&plug->cached_rqs);
    if (!rq || rq->q != q)
        return NULL;
    if (type != rq->mq_hctx->type &&
        (type != HCTX_TYPE_READ || rq->mq_hctx->type != HCTX_TYPE_DEFAULT))
        return NULL;
    if (op_is_flush(rq->cmd_flags) != op_is_flush(opf))
        return NULL;
    return rq;
}

static bool bio_unaligned(const struct bio *bio, struct request_queue *q)
{
    unsigned int bs_mask = queue_logical_block_size(q) - 1;

    /* .bi_sector of any zero sized bio need to be initialized */
    if ((bio->bi_iter.bi_size & bs_mask) ||
        ((bio->bi_iter.bi_sector << SECTOR_SHIFT) & bs_mask))
        return true;
    return false;
}

static bool blk_mq_attempt_bio_merge(struct request_queue *q,
                     struct bio *bio, unsigned int nr_segs)
{
    if (!blk_queue_nomerges(q) && bio_mergeable(bio)) {
        if (blk_attempt_plug_merge(q, bio, nr_segs))
            return true;
        if (blk_mq_sched_bio_merge(q, bio, nr_segs))
            return true;
    }
    return false;
}

static inline struct request *
__blk_mq_alloc_requests_batch(struct blk_mq_alloc_data *data)
{
    PANIC("");
}

/* Set start and alloc time when the allocated request is actually used */
static inline void blk_mq_rq_time_init(struct request *rq, u64 alloc_time_ns)
{
    if (blk_mq_need_time_stamp(rq))
        rq->start_time_ns = blk_time_get_ns();
    else
        rq->start_time_ns = 0;

#ifdef CONFIG_BLK_RQ_ALLOC_TIME
    if (blk_queue_rq_alloc_time(rq->q))
        rq->alloc_time_ns = alloc_time_ns ?: rq->start_time_ns;
    else
        rq->alloc_time_ns = 0;
#endif
}

static struct request *blk_mq_rq_ctx_init(struct blk_mq_alloc_data *data,
        struct blk_mq_tags *tags, unsigned int tag)
{
    struct blk_mq_ctx *ctx = data->ctx;
    struct blk_mq_hw_ctx *hctx = data->hctx;
    struct request_queue *q = data->q;
    struct request *rq = tags->static_rqs[tag];

    rq->q = q;
    rq->mq_ctx = ctx;
    rq->mq_hctx = hctx;
    rq->cmd_flags = data->cmd_flags;

    if (data->flags & BLK_MQ_REQ_PM)
        data->rq_flags |= RQF_PM;
    if (blk_queue_io_stat(q))
        data->rq_flags |= RQF_IO_STAT;
    rq->rq_flags = data->rq_flags;

    if (data->rq_flags & RQF_SCHED_TAGS) {
        rq->tag = BLK_MQ_NO_TAG;
        rq->internal_tag = tag;
    } else {
        rq->tag = tag;
        rq->internal_tag = BLK_MQ_NO_TAG;
    }
    rq->timeout = 0;

    rq->part = NULL;
    rq->io_start_time_ns = 0;
    rq->stats_sectors = 0;
    rq->nr_phys_segments = 0;
    rq->nr_integrity_segments = 0;
    rq->end_io = NULL;
    rq->end_io_data = NULL;

    blk_crypto_rq_set_defaults(rq);
    INIT_LIST_HEAD(&rq->queuelist);
    /* tag was already set */
    WRITE_ONCE(rq->deadline, 0);
    req_ref_set(rq, 1);

    if (rq->rq_flags & RQF_USE_SCHED) {
        struct elevator_queue *e = data->q->elevator;

        INIT_HLIST_NODE(&rq->hash);
        RB_CLEAR_NODE(&rq->rb_node);

        if (e->type->ops.prepare_request)
            e->type->ops.prepare_request(rq);
    }

    return rq;
}

static struct request *__blk_mq_alloc_requests(struct blk_mq_alloc_data *data)
{
    struct request_queue *q = data->q;
    u64 alloc_time_ns = 0;
    struct request *rq;
    unsigned int tag;

    /* alloc_time includes depth and tag waits */
    if (blk_queue_rq_alloc_time(q))
        alloc_time_ns = blk_time_get_ns();

    if (data->cmd_flags & REQ_NOWAIT)
        data->flags |= BLK_MQ_REQ_NOWAIT;

retry:
    data->ctx = blk_mq_get_ctx(q);
    data->hctx = blk_mq_map_queue(q, data->cmd_flags, data->ctx);

    if (q->elevator) {
        /*
         * All requests use scheduler tags when an I/O scheduler is
         * enabled for the queue.
         */
        data->rq_flags |= RQF_SCHED_TAGS;

        /*
         * Flush/passthrough requests are special and go directly to the
         * dispatch list.
         */
        if ((data->cmd_flags & REQ_OP_MASK) != REQ_OP_FLUSH &&
            !blk_op_is_passthrough(data->cmd_flags)) {
            struct elevator_mq_ops *ops = &q->elevator->type->ops;

            WARN_ON_ONCE(data->flags & BLK_MQ_REQ_RESERVED);

            data->rq_flags |= RQF_USE_SCHED;
            if (ops->limit_depth)
                ops->limit_depth(data->cmd_flags, data);
        }
    } else {
        blk_mq_tag_busy(data->hctx);
    }

    if (data->flags & BLK_MQ_REQ_RESERVED)
        data->rq_flags |= RQF_RESV;

    /*
     * Try batched alloc if we want more than 1 tag.
     */
    if (data->nr_tags > 1) {
        rq = __blk_mq_alloc_requests_batch(data);
        if (rq) {
            blk_mq_rq_time_init(rq, alloc_time_ns);
            return rq;
        }
        data->nr_tags = 1;
    }

    /*
     * Waiting allocations only fail because of an inactive hctx.  In that
     * case just retry the hctx assignment and tag allocation as CPU hotplug
     * should have migrated us to an online CPU by now.
     */
    tag = blk_mq_get_tag(data);
    if (tag == BLK_MQ_NO_TAG) {
        if (data->flags & BLK_MQ_REQ_NOWAIT)
            return NULL;
        /*
         * Give up the CPU and sleep for a random short time to
         * ensure that thread using a realtime scheduling class
         * are migrated off the CPU, and thus off the hctx that
         * is going away.
         */
        msleep(3);
        goto retry;
    }

    if (!(data->rq_flags & RQF_SCHED_TAGS))
        blk_mq_inc_active_requests(data->hctx);
    rq = blk_mq_rq_ctx_init(data, blk_mq_tags_from_data(data), tag);
    blk_mq_rq_time_init(rq, alloc_time_ns);
    return rq;
}

static struct request *blk_mq_get_new_requests(struct request_queue *q,
                           struct blk_plug *plug,
                           struct bio *bio,
                           unsigned int nsegs)
{
    struct blk_mq_alloc_data data = {
        .q      = q,
        .nr_tags    = 1,
        .cmd_flags  = bio->bi_opf,
    };
    struct request *rq;

    rq_qos_throttle(q, bio);

    if (plug) {
        data.nr_tags = plug->nr_ios;
        plug->nr_ios = 1;
        data.cached_rqs = &plug->cached_rqs;
    }

    rq = __blk_mq_alloc_requests(&data);
    if (rq)
        return rq;
#if 0
    rq_qos_cleanup(q, bio);
    if (bio->bi_opf & REQ_NOWAIT)
        bio_wouldblock_error(bio);
#endif
    PANIC("");
    return NULL;
}

static void blk_mq_use_cached_rq(struct request *rq, struct blk_plug *plug,
        struct bio *bio)
{
#if 0
    if (rq_list_pop(&plug->cached_rqs) != rq)
        WARN_ON_ONCE(1);

    /*
     * If any qos ->throttle() end up blocking, we will have flushed the
     * plug and hence killed the cached_rq list as well. Pop this entry
     * before we throttle.
     */
    rq_qos_throttle(rq->q, bio);

    blk_mq_rq_time_init(rq, 0);
    rq->cmd_flags = bio->bi_opf;
    INIT_LIST_HEAD(&rq->queuelist);
#endif
    PANIC("");
}

static inline void blk_account_io_start(struct request *req)
{
    trace_block_io_start(req);

    if (blk_do_io_stat(req)) {
        /*
         * All non-passthrough requests are created from a bio with one
         * exception: when a flush command that is part of a flush sequence
         * generated by the state machine in blk-flush.c is cloned onto the
         * lower device by dm-multipath we can get here without a bio.
         */
        if (req->bio)
            req->part = req->bio->bi_bdev;
        else
            req->part = req->q->disk->part0;

        part_stat_lock();
        update_io_ticks(req->part, jiffies, false);
        part_stat_local_inc(req->part,
                    in_flight[op_is_write(req_op(req))]);
        part_stat_unlock();
    }
}

static void blk_mq_bio_to_request(struct request *rq, struct bio *bio,
        unsigned int nr_segs)
{
    int err;

    if (bio->bi_opf & REQ_RAHEAD)
        rq->cmd_flags |= REQ_FAILFAST_MASK;

    rq->__sector = bio->bi_iter.bi_sector;
    blk_rq_bio_prep(rq, bio, nr_segs);
    if (bio_integrity(bio))
        rq->nr_integrity_segments = blk_rq_count_integrity_sg(rq->q,
                                      bio);

    /* This can't fail, since GFP_NOIO includes __GFP_DIRECT_RECLAIM. */
    err = blk_crypto_rq_bio_prep(rq, bio, GFP_NOIO);
    WARN_ON_ONCE(err);

    blk_account_io_start(rq);
}

/*
 * Allow 2x BLK_MAX_REQUEST_COUNT requests on plug queue for multiple
 * queues. This is important for md arrays to benefit from merging
 * requests.
 */
static inline unsigned short blk_plug_max_rq_count(struct blk_plug *plug)
{
    if (plug->multiple_queues)
        return BLK_MAX_REQUEST_COUNT * 2;
    return BLK_MAX_REQUEST_COUNT;
}

static void blk_add_rq_to_plug(struct blk_plug *plug, struct request *rq)
{
    struct request *last = rq_list_peek(&plug->mq_list);

    if (!plug->rq_count) {
        trace_block_plug(rq->q);
    } else if (plug->rq_count >= blk_plug_max_rq_count(plug) ||
           (!blk_queue_nomerges(rq->q) &&
            blk_rq_bytes(last) >= BLK_PLUG_FLUSH_SIZE)) {
        blk_mq_flush_plug_list(plug, false);
        last = NULL;
        trace_block_plug(rq->q);
    }

    if (!plug->multiple_queues && last && last->q != rq->q)
        plug->multiple_queues = true;
    /*
     * Any request allocated from sched tags can't be issued to
     * ->queue_rqs() directly
     */
    if (!plug->has_elevator && (rq->rq_flags & RQF_SCHED_TAGS))
        plug->has_elevator = true;
    rq_list_add_tail(&plug->mq_list, rq);
    plug->rq_count++;
}

/**
 * blk_mq_submit_bio - Create and send a request to block device.
 * @bio: Bio pointer.
 *
 * Builds up a request structure from @q and @bio and send to the device. The
 * request may not be queued directly to hardware if:
 * * This request can be merged with another one
 * * We want to place request at plug queue for possible future merging
 * * There is an IO scheduler active at this queue
 *
 * It will not queue the request if there is an error with the bio, or at the
 * request creation.
 */
void blk_mq_submit_bio(struct bio *bio)
{
    struct request_queue *q = bdev_get_queue(bio->bi_bdev);
    struct blk_plug *plug = current->plug;
    const int is_sync = op_is_sync(bio->bi_opf);
    struct blk_mq_hw_ctx *hctx;
    unsigned int nr_segs;
    struct request *rq;
    blk_status_t ret;

    /*
     * If the plug has a cached request for this queue, try to use it.
     */
    rq = blk_mq_peek_cached_request(plug, q, bio->bi_opf);

    /*
     * A BIO that was released from a zone write plug has already been
     * through the preparation in this function, already holds a reference
     * on the queue usage counter, and is the only write BIO in-flight for
     * the target zone. Go straight to preparing a request for it.
     */
    if (bio_zone_write_plugging(bio)) {
        nr_segs = bio->__bi_nr_segments;
        if (rq)
            blk_queue_exit(q);
        goto new_request;
    }

    bio = blk_queue_bounce(bio, q);

    /*
     * The cached request already holds a q_usage_counter reference and we
     * don't have to acquire a new one if we use it.
     */
    if (!rq) {
#if 0
        if (unlikely(bio_queue_enter(bio)))
            return;
#endif
        pr_err("%s: No bio_queue_enter\n", __func__);
    }

    /*
     * Device reconfiguration may change logical block size or reduce the
     * number of poll queues, so the checks for alignment and poll support
     * have to be done with queue usage counter held.
     */
    if (unlikely(bio_unaligned(bio, q))) {
        bio_io_error(bio);
        goto queue_exit;
    }

    if ((bio->bi_opf & REQ_POLLED) && !blk_mq_can_poll(q)) {
        bio->bi_status = BLK_STS_NOTSUPP;
        bio_endio(bio);
        goto queue_exit;
    }

    bio = __bio_split_to_limits(bio, &q->limits, &nr_segs);
    if (!bio)
        goto queue_exit;

    if (!bio_integrity_prep(bio))
        goto queue_exit;

    if (blk_mq_attempt_bio_merge(q, bio, nr_segs))
        goto queue_exit;

    if (blk_queue_is_zoned(q) && blk_zone_plug_bio(bio, nr_segs))
        goto queue_exit;

new_request:
    if (!rq) {
        rq = blk_mq_get_new_requests(q, plug, bio, nr_segs);
        if (unlikely(!rq))
            goto queue_exit;
    } else {
        blk_mq_use_cached_rq(rq, plug, bio);
    }

    trace_block_getrq(bio);

    rq_qos_track(q, rq, bio);

    blk_mq_bio_to_request(rq, bio, nr_segs);

    ret = blk_crypto_rq_get_keyslot(rq);
    if (ret != BLK_STS_OK) {
        bio->bi_status = ret;
        bio_endio(bio);
        blk_mq_free_request(rq);
        return;
    }

    if (bio_zone_write_plugging(bio))
        blk_zone_write_plug_init_request(rq);

    printk("%s: step1\n", __func__);
    if (op_is_flush(bio->bi_opf) && blk_insert_flush(rq))
        return;

    printk("%s: step2\n", __func__);
    if (plug) {
        blk_add_rq_to_plug(plug, rq);
        return;
    }

#if 0
    hctx = rq->mq_hctx;
    if ((rq->rq_flags & RQF_USE_SCHED) ||
        (hctx->dispatch_busy && (q->nr_hw_queues == 1 || !is_sync))) {
        blk_mq_insert_request(rq, 0);
        blk_mq_run_hw_queue(hctx, true);
    } else {
        blk_mq_run_dispatch_ops(q, blk_mq_try_issue_directly(hctx, rq));
    }
#endif

    PANIC("");
    return;

queue_exit:
    /*
     * Don't drop the queue reference if we were trying to use a cached
     * request and thus didn't acquire one.
     */
    if (!rq)
        blk_queue_exit(q);

    PANIC("ERR");
}

static void __blk_mq_flush_plug_list(struct request_queue *q,
                     struct blk_plug *plug)
{
    if (blk_queue_quiesced(q))
        return;
    q->mq_ops->queue_rqs(&plug->mq_list);
}

void blk_mq_flush_plug_list(struct blk_plug *plug, bool from_schedule)
{
    struct request *rq;
    unsigned int depth;

    /*
     * We may have been called recursively midway through handling
     * plug->mq_list via a schedule() in the driver's queue_rq() callback.
     * To avoid mq_list changing under our feet, clear rq_count early and
     * bail out specifically if rq_count is 0 rather than checking
     * whether the mq_list is empty.
     */
    if (plug->rq_count == 0)
        return;
    depth = plug->rq_count;
    plug->rq_count = 0;

    if (!plug->multiple_queues && !plug->has_elevator && !from_schedule) {
        struct request_queue *q;

        rq = rq_list_peek(&plug->mq_list);
        q = rq->q;
        trace_block_unplug(q, depth, true);

        /*
         * Peek first request and see if we have a ->queue_rqs() hook.
         * If we do, we can dispatch the whole plug list in one go. We
         * already know at this point that all requests belong to the
         * same queue, caller must ensure that's the case.
         */
        if (q->mq_ops->queue_rqs) {
            blk_mq_run_dispatch_ops(q,
                __blk_mq_flush_plug_list(q, plug));
            if (rq_list_empty(&plug->mq_list))
                return;
        }

#if 0
        blk_mq_run_dispatch_ops(q,
                blk_mq_plug_issue_direct(plug));
        if (rq_list_empty(&plug->mq_list))
            return;
#endif

        PANIC("stage1");
    }

#if 0
    do {
        blk_mq_dispatch_plug_list(plug, from_schedule);
    } while (!rq_list_empty(&plug->mq_list));
#endif
    PANIC("");
}

/**
 * blk_mq_start_request - Start processing a request
 * @rq: Pointer to request to be started
 *
 * Function used by device drivers to notify the block layer that a request
 * is going to be processed now, so blk layer can do proper initializations
 * such as starting the timeout timer.
 */
void blk_mq_start_request(struct request *rq)
{
    struct request_queue *q = rq->q;

    trace_block_rq_issue(rq);

    if (test_bit(QUEUE_FLAG_STATS, &q->queue_flags) &&
        !blk_rq_is_passthrough(rq)) {
        rq->io_start_time_ns = blk_time_get_ns();
        rq->stats_sectors = blk_rq_sectors(rq);
        rq->rq_flags |= RQF_STATS;
        rq_qos_issue(q, rq);
    }

    WARN_ON_ONCE(blk_mq_rq_state(rq) != MQ_RQ_IDLE);

    blk_add_timer(rq);
    WRITE_ONCE(rq->state, MQ_RQ_IN_FLIGHT);
    rq->mq_hctx->tags->rqs[rq->tag] = rq;

    if (blk_integrity_rq(rq) && req_op(rq) == REQ_OP_WRITE)
        blk_integrity_prepare(rq);

    if (rq->bio && rq->bio->bi_opf & REQ_POLLED)
            WRITE_ONCE(rq->bio->bi_cookie, rq->mq_hctx->queue_num);
}

/**
 * blk_mq_complete_request - end I/O on a request
 * @rq:     the request being processed
 *
 * Description:
 *  Complete a request by scheduling the ->complete_rq operation.
 **/
void blk_mq_complete_request(struct request *rq)
{
    if (!blk_mq_complete_request_remote(rq))
        rq->q->mq_ops->complete(rq);
}

bool blk_mq_complete_request_remote(struct request *rq)
{
    WRITE_ONCE(rq->state, MQ_RQ_COMPLETE);

    /*
     * For request which hctx has only one ctx mapping,
     * or a polled request, always complete locally,
     * it's pointless to redirect the completion.
     */
    if ((rq->mq_hctx->nr_ctx == 1 &&
         rq->mq_ctx->cpu == raw_smp_processor_id()) ||
         rq->cmd_flags & REQ_POLLED)
        return false;

#if 0
    if (blk_mq_complete_need_ipi(rq)) {
        blk_mq_complete_send_ipi(rq);
        return true;
    }

    if (rq->q->nr_hw_queues == 1) {
        blk_mq_raise_softirq(rq);
        return true;
    }
    return false;
#endif
    PANIC("");
}

void blk_mq_end_request(struct request *rq, blk_status_t error)
{
    if (blk_update_request(rq, error, blk_rq_bytes(rq)))
        BUG();
    __blk_mq_end_request(rq, error);
}

static void blk_print_req_error(struct request *req, blk_status_t status)
{
#if 0
    printk_ratelimited(KERN_ERR
        "%s error, dev %s, sector %llu op 0x%x:(%s) flags 0x%x "
        "phys_seg %u prio class %u\n",
        blk_status_to_str(status),
        req->q->disk ? req->q->disk->disk_name : "?",
        blk_rq_pos(req), (__force u32)req_op(req),
        blk_op_str(req_op(req)),
        (__force u32)(req->cmd_flags & ~REQ_OP_MASK),
        req->nr_phys_segments,
        IOPRIO_PRIO_CLASS(req_get_ioprio(req)));
#endif
    PANIC("");
}

static void blk_account_io_completion(struct request *req, unsigned int bytes)
{
    if (req->part && blk_do_io_stat(req)) {
        const int sgrp = op_stat_group(req_op(req));

        part_stat_lock();
        part_stat_add(req->part, sectors[sgrp], bytes >> 9);
        part_stat_unlock();
    }
}

/**
 * blk_update_request - Complete multiple bytes without completing the request
 * @req:      the request being processed
 * @error:    block status code
 * @nr_bytes: number of bytes to complete for @req
 *
 * Description:
 *     Ends I/O on a number of bytes attached to @req, but doesn't complete
 *     the request structure even if @req doesn't have leftover.
 *     If @req has leftover, sets it up for the next range of segments.
 *
 *     Passing the result of blk_rq_bytes() as @nr_bytes guarantees
 *     %false return from this function.
 *
 * Note:
 *  The RQF_SPECIAL_PAYLOAD flag is ignored on purpose in this function
 *      except in the consistency check at the end of this function.
 *
 * Return:
 *     %false - this request doesn't have any more data
 *     %true  - this request has more data
 **/
bool blk_update_request(struct request *req, blk_status_t error,
        unsigned int nr_bytes)
{
    bool is_flush = req->rq_flags & RQF_FLUSH_SEQ;
    bool quiet = req->rq_flags & RQF_QUIET;
    int total_bytes;

    trace_block_rq_complete(req, error, nr_bytes);

    if (!req->bio)
        return false;

    if (blk_integrity_rq(req) && req_op(req) == REQ_OP_READ &&
        error == BLK_STS_OK)
        blk_integrity_complete(req, nr_bytes);

    /*
     * Upper layers may call blk_crypto_evict_key() anytime after the last
     * bio_endio().  Therefore, the keyslot must be released before that.
     */
    if (blk_crypto_rq_has_keyslot(req) && nr_bytes >= blk_rq_bytes(req))
        __blk_crypto_rq_put_keyslot(req);

    if (unlikely(error && !blk_rq_is_passthrough(req) && !quiet) &&
        !test_bit(GD_DEAD, &req->q->disk->state)) {
        blk_print_req_error(req, error);
        trace_block_rq_error(req, error, nr_bytes);
    }

    blk_account_io_completion(req, nr_bytes);

    total_bytes = 0;
    while (req->bio) {
        struct bio *bio = req->bio;
        unsigned bio_bytes = min(bio->bi_iter.bi_size, nr_bytes);

        if (unlikely(error))
            bio->bi_status = error;

        if (bio_bytes == bio->bi_iter.bi_size) {
            req->bio = bio->bi_next;
        } else if (bio_is_zone_append(bio) && error == BLK_STS_OK) {
            /*
             * Partial zone append completions cannot be supported
             * as the BIO fragments may end up not being written
             * sequentially.
             */
            bio->bi_status = BLK_STS_IOERR;
        }

        /* Completion has already been traced */
        bio_clear_flag(bio, BIO_TRACE_COMPLETION);
        if (unlikely(quiet))
            bio_set_flag(bio, BIO_QUIET);

        bio_advance(bio, bio_bytes);

        /* Don't actually finish bio if it's part of flush sequence */
        if (!bio->bi_iter.bi_size) {
            blk_zone_update_request_bio(req, bio);
            if (!is_flush)
                bio_endio(bio);
        }

        total_bytes += bio_bytes;
        nr_bytes -= bio_bytes;

        if (!nr_bytes)
            break;
    }

    /*
     * completely done
     */
    if (!req->bio) {
        /*
         * Reset counters so that the request stacking driver
         * can find how many bytes remain in the request
         * later.
         */
        req->__data_len = 0;
        return false;
    }

    req->__data_len -= total_bytes;

    /* update sector only for requests with clear definition of sector */
    if (!blk_rq_is_passthrough(req))
        req->__sector += total_bytes >> 9;

    /* mixed attributes always follow the first bio */
    if (req->rq_flags & RQF_MIXED_MERGE) {
        req->cmd_flags &= ~REQ_FAILFAST_MASK;
        req->cmd_flags |= req->bio->bi_opf & REQ_FAILFAST_MASK;
    }

    if (!(req->rq_flags & RQF_SPECIAL_PAYLOAD)) {
        /*
         * If total number of sectors is less than the first segment
         * size, something has gone terribly wrong.
         */
        if (blk_rq_bytes(req) < blk_rq_cur_bytes(req)) {
            blk_dump_rq_flags(req, "request botched");
            req->__data_len = blk_rq_cur_bytes(req);
        }

        /* recalculate the number of segments */
        req->nr_phys_segments = blk_recalc_rq_segments(req);
    }

    PANIC("");
    return true;
}

static inline void blk_account_io_done(struct request *req, u64 now)
{
    pr_err("%s: No impl.", __func__);
}

static inline void __blk_mq_end_request_acct(struct request *rq, u64 now)
{
    if (rq->rq_flags & RQF_STATS)
        blk_stat_add(rq, now);

    blk_mq_sched_completed_request(rq, now);
    blk_account_io_done(rq, now);
}

static void blk_mq_finish_request(struct request *rq)
{
    struct request_queue *q = rq->q;

    blk_zone_finish_request(rq);

    if (rq->rq_flags & RQF_USE_SCHED) {
        q->elevator->type->ops.finish_request(rq);
        /*
         * For postflush request that may need to be
         * completed twice, we should clear this flag
         * to avoid double finish_request() on the rq.
         */
        rq->rq_flags &= ~RQF_USE_SCHED;
    }
}

inline void __blk_mq_end_request(struct request *rq, blk_status_t error)
{
    if (blk_mq_need_time_stamp(rq))
        __blk_mq_end_request_acct(rq, blk_time_get_ns());

    blk_mq_finish_request(rq);

    if (rq->end_io) {
        rq_qos_done(rq->q, rq);
        if (rq->end_io(rq, error) == RQ_END_IO_FREE)
            blk_mq_free_request(rq);
    } else {
        blk_mq_free_request(rq);
    }
}

static void __blk_mq_free_request(struct request *rq)
{
    struct request_queue *q = rq->q;
    struct blk_mq_ctx *ctx = rq->mq_ctx;
    struct blk_mq_hw_ctx *hctx = rq->mq_hctx;
    const int sched_tag = rq->internal_tag;

    blk_crypto_free_request(rq);
    blk_pm_mark_last_busy(rq);
    rq->mq_hctx = NULL;

    if (rq->tag != BLK_MQ_NO_TAG) {
        blk_mq_dec_active_requests(hctx);
        blk_mq_put_tag(hctx->tags, ctx, rq->tag);
    }
    if (sched_tag != BLK_MQ_NO_TAG)
        blk_mq_put_tag(hctx->sched_tags, ctx, sched_tag);
    blk_mq_sched_restart(hctx);
    blk_queue_exit(q);
}

void blk_mq_free_request(struct request *rq)
{
    struct request_queue *q = rq->q;

    blk_mq_finish_request(rq);

    if (unlikely(laptop_mode && !blk_rq_is_passthrough(rq)))
        laptop_io_completion(q->disk->bdi);

    rq_qos_done(q, rq);

    WRITE_ONCE(rq->state, MQ_RQ_IDLE);
    if (req_ref_put_and_test(rq))
        __blk_mq_free_request(rq);
}

void blk_mq_start_stopped_hw_queues(struct request_queue *q, bool async)
{
    struct blk_mq_hw_ctx *hctx;
    unsigned long i;

    queue_for_each_hw_ctx(q, hctx, i)
        blk_mq_start_stopped_hw_queue(hctx, async ||
                    (hctx->flags & BLK_MQ_F_BLOCKING));
}

void blk_mq_start_stopped_hw_queue(struct blk_mq_hw_ctx *hctx, bool async)
{
    if (!blk_mq_hctx_stopped(hctx))
        return;

    clear_bit(BLK_MQ_S_STOPPED, &hctx->state);
    /*
     * Pairs with the smp_mb() in blk_mq_hctx_stopped() to order the
     * clearing of BLK_MQ_S_STOPPED above and the checking of dispatch
     * list in the subsequent routine.
     */
    smp_mb__after_atomic();
    blk_mq_run_hw_queue(hctx, async);
}

void blk_mq_kick_requeue_list(struct request_queue *q)
{
    printk("%s: ...\n", __func__);
    kblockd_mod_delayed_work_on(WORK_CPU_UNBOUND, &q->requeue_work, 0);
}

void blk_rq_init(struct request_queue *q, struct request *rq)
{
    memset(rq, 0, sizeof(*rq));

    INIT_LIST_HEAD(&rq->queuelist);
    rq->q = q;
    rq->__sector = (sector_t) -1;
    INIT_HLIST_NODE(&rq->hash);
    RB_CLEAR_NODE(&rq->rb_node);
    rq->tag = BLK_MQ_NO_TAG;
    rq->internal_tag = BLK_MQ_NO_TAG;
    rq->start_time_ns = blk_time_get_ns();
    rq->part = NULL;
    blk_crypto_rq_set_defaults(rq);
}

/*
 * Mark us waiting for a tag. For shared tags, this involves hooking us into
 * the tag wakeups. For non-shared tags, we can simply mark us needing a
 * restart. For both cases, take care to check the condition again after
 * marking us as waiting.
 */
static bool blk_mq_mark_tag_wait(struct blk_mq_hw_ctx *hctx,
                 struct request *rq)
{
    struct sbitmap_queue *sbq;
    struct wait_queue_head *wq;
    wait_queue_entry_t *wait;
    bool ret;


    PANIC("");
}

bool __blk_mq_alloc_driver_tag(struct request *rq)
{
    struct sbitmap_queue *bt = &rq->mq_hctx->tags->bitmap_tags;
    unsigned int tag_offset = rq->mq_hctx->tags->nr_reserved_tags;
    int tag;

#if 0
    blk_mq_tag_busy(rq->mq_hctx);

    if (blk_mq_tag_is_reserved(rq->mq_hctx->sched_tags, rq->internal_tag)) {
        bt = &rq->mq_hctx->tags->breserved_tags;
        tag_offset = 0;
    } else {
        if (!hctx_may_queue(rq->mq_hctx, bt))
            return false;
    }

    tag = __sbitmap_queue_get(bt);
    if (tag == BLK_MQ_NO_TAG)
        return false;

    rq->tag = tag + tag_offset;
    blk_mq_inc_active_requests(rq->mq_hctx);
    return true;
#endif
    PANIC("");
}

static enum prep_dispatch blk_mq_prep_dispatch_rq(struct request *rq,
                          bool need_budget)
{
    struct blk_mq_hw_ctx *hctx = rq->mq_hctx;
    int budget_token = -1;

    if (need_budget) {
        budget_token = blk_mq_get_dispatch_budget(rq->q);
        if (budget_token < 0) {
            blk_mq_put_driver_tag(rq);
            return PREP_DISPATCH_NO_BUDGET;
        }
        blk_mq_set_rq_budget_token(rq, budget_token);
    }

    if (!blk_mq_get_driver_tag(rq)) {
        /*
         * The initial allocation attempt failed, so we need to
         * rerun the hardware queue when a tag is freed. The
         * waitqueue takes care of that. If the queue is run
         * before we add this entry back on the dispatch list,
         * we'll re-run it below.
         */
        if (!blk_mq_mark_tag_wait(hctx, rq)) {
            /*
             * All budgets not got from this function will be put
             * together during handling partial dispatch
             */
            if (need_budget)
                blk_mq_put_dispatch_budget(rq->q, budget_token);
            return PREP_DISPATCH_NO_TAG;
        }
    }

    return PREP_DISPATCH_OK;
}

/*
 * blk_mq_commit_rqs will notify driver using bd->last that there is no
 * more requests. (See comment in struct blk_mq_ops for commit_rqs for
 * details)
 * Attention, we should explicitly call this in unusual cases:
 *  1) did not queue everything initially scheduled to queue
 *  2) the last attempt to queue a request failed
 */
static void blk_mq_commit_rqs(struct blk_mq_hw_ctx *hctx, int queued,
                  bool from_schedule)
{
    if (hctx->queue->mq_ops->commit_rqs && queued) {
        trace_block_unplug(hctx->queue, queued, !from_schedule);
        hctx->queue->mq_ops->commit_rqs(hctx);
    }
}

#define BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT  8
#define BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR  4
/*
 * Update dispatch busy with the Exponential Weighted Moving Average(EWMA):
 * - EWMA is one simple way to compute running average value
 * - weight(7/8 and 1/8) is applied so that it can decrease exponentially
 * - take 4 as factor for avoiding to get too small(0) result, and this
 *   factor doesn't matter because EWMA decreases exponentially
 */
static void blk_mq_update_dispatch_busy(struct blk_mq_hw_ctx *hctx, bool busy)
{
    unsigned int ewma;

    ewma = hctx->dispatch_busy;

    if (!ewma && !busy)
        return;

    ewma *= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT - 1;
    if (busy)
        ewma += 1 << BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR;
    ewma /= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT;

    hctx->dispatch_busy = ewma;
}

/*
 * Returns true if we did some work AND can potentially do more.
 */
bool blk_mq_dispatch_rq_list(struct blk_mq_hw_ctx *hctx, struct list_head *list,
                 unsigned int nr_budgets)
{
    enum prep_dispatch prep;
    struct request_queue *q = hctx->queue;
    struct request *rq;
    int queued;
    blk_status_t ret = BLK_STS_OK;
    bool needs_resource = false;

    if (list_empty(list))
        return false;

    /*
     * Now process all the entries, sending them to the driver.
     */
    queued = 0;
    do {
        struct blk_mq_queue_data bd;

        rq = list_first_entry(list, struct request, queuelist);

        WARN_ON_ONCE(hctx != rq->mq_hctx);
        prep = blk_mq_prep_dispatch_rq(rq, !nr_budgets);
        if (prep != PREP_DISPATCH_OK)
            break;

        list_del_init(&rq->queuelist);

        bd.rq = rq;
        bd.last = list_empty(list);

        /*
         * once the request is queued to lld, no need to cover the
         * budget any more
         */
        if (nr_budgets)
            nr_budgets--;

    printk("%s: step1\n", __func__);
        ret = q->mq_ops->queue_rq(hctx, &bd);
    printk("%s: step2\n", __func__);
        switch (ret) {
        case BLK_STS_OK:
            queued++;
            break;
        case BLK_STS_RESOURCE:
            needs_resource = true;
            fallthrough;
        case BLK_STS_DEV_RESOURCE:
            blk_mq_handle_dev_resource(rq, list);
            goto out;
        default:
            blk_mq_end_request(rq, ret);
        }
    } while (!list_empty(list));
out:
    /* If we didn't flush the entire list, we could have told the driver
     * there was more coming, but that turned out to be a lie.
     */
    if (!list_empty(list) || ret != BLK_STS_OK)
        blk_mq_commit_rqs(hctx, queued, false);

    /*
     * Any items that need requeuing? Stuff them into hctx->dispatch,
     * that is where we will continue on next queue run.
     */
    if (!list_empty(list)) {
        PANIC("stage1");
    }

    printk("%s: step3\n", __func__);
    blk_mq_update_dispatch_busy(hctx, false);
    return true;
}

struct dispatch_rq_data {
    struct blk_mq_hw_ctx *hctx;
    struct request *rq;
};

static bool dispatch_rq_from_ctx(struct sbitmap *sb, unsigned int bitnr,
        void *data)
{
    struct dispatch_rq_data *dispatch_data = data;
    struct blk_mq_hw_ctx *hctx = dispatch_data->hctx;
    struct blk_mq_ctx *ctx = hctx->ctxs[bitnr];
    enum hctx_type type = hctx->type;

    spin_lock(&ctx->lock);
    if (!list_empty(&ctx->rq_lists[type])) {
        dispatch_data->rq = list_entry_rq(ctx->rq_lists[type].next);
        list_del_init(&dispatch_data->rq->queuelist);
        if (list_empty(&ctx->rq_lists[type]))
            sbitmap_clear_bit(sb, bitnr);
    }
    spin_unlock(&ctx->lock);

    return !dispatch_data->rq;
}

struct request *blk_mq_dequeue_from_ctx(struct blk_mq_hw_ctx *hctx,
                    struct blk_mq_ctx *start)
{
    unsigned off = start ? start->index_hw[hctx->type] : 0;
    struct dispatch_rq_data data = {
        .hctx = hctx,
        .rq   = NULL,
    };

    __sbitmap_for_each_set(&hctx->ctx_map, off,
                   dispatch_rq_from_ctx, &data);

    return data.rq;
}
