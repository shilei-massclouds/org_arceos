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

    //INIT_DELAYED_WORK(&q->requeue_work, blk_mq_requeue_work);
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
    printk("%s: step1\n", __func__);
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

    if (op_is_flush(bio->bi_opf) && blk_insert_flush(rq))
        return;

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
