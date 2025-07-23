#include <linux/bio.h>
#include <linux/blkdev.h>

#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-pm.h"
#include "blk-cgroup.h"
#include "blk-throttle.h"
#include "blk-ioprio.h"

#include "../adaptor.h"

static DEFINE_IDA(blk_queue_ida);

/*
 * For queue allocation
 */
static struct kmem_cache *blk_requestq_cachep;

struct request_queue *blk_alloc_queue(struct queue_limits *lim, int node_id)
{
    struct request_queue *q;
    int error;

    q = kmem_cache_alloc_node(blk_requestq_cachep, GFP_KERNEL | __GFP_ZERO,
                  node_id);
    if (!q)
        return ERR_PTR(-ENOMEM);

    q->last_merge = NULL;

    q->id = ida_alloc(&blk_queue_ida, GFP_KERNEL);
    if (q->id < 0) {
        error = q->id;
        goto fail_q;
    }

    q->stats = blk_alloc_queue_stats();
    if (!q->stats) {
        error = -ENOMEM;
        goto fail_id;
    }

    error = blk_set_default_limits(lim);
    if (error)
        goto fail_stats;
    q->limits = *lim;

    q->node = node_id;

    atomic_set(&q->nr_active_requests_shared_tags, 0);

#if 0
    timer_setup(&q->timeout, blk_rq_timed_out_timer, 0);
    INIT_WORK(&q->timeout_work, blk_timeout_work);
#endif
    INIT_LIST_HEAD(&q->icq_list);

    refcount_set(&q->refs, 1);
    mutex_init(&q->debugfs_mutex);
    mutex_init(&q->sysfs_lock);
    mutex_init(&q->sysfs_dir_lock);
    mutex_init(&q->limits_lock);
    mutex_init(&q->rq_qos_mutex);
    spin_lock_init(&q->queue_lock);

    init_waitqueue_head(&q->mq_freeze_wq);
    mutex_init(&q->mq_freeze_lock);

    //blkg_init_queue(q);

#if 0
    /*
     * Init percpu_ref in atomic mode so that it's faster to shutdown.
     * See blk_register_queue() for details.
     */
    error = percpu_ref_init(&q->q_usage_counter,
                blk_queue_usage_counter_release,
                PERCPU_REF_INIT_ATOMIC, GFP_KERNEL);
    if (error)
        goto fail_stats;
#endif
    lockdep_register_key(&q->io_lock_cls_key);
    lockdep_register_key(&q->q_lock_cls_key);
    lockdep_init_map(&q->io_lockdep_map, "&q->q_usage_counter(io)",
             &q->io_lock_cls_key, 0);
    lockdep_init_map(&q->q_lockdep_map, "&q->q_usage_counter(queue)",
             &q->q_lock_cls_key, 0);

    q->nr_requests = BLKDEV_DEFAULT_RQ;

    return q;

fail_stats:
    blk_free_queue_stats(q->stats);
fail_id:
    ida_free(&blk_queue_ida, q->id);
fail_q:
    kmem_cache_free(blk_requestq_cachep, q);
    return ERR_PTR(error);
}

int __init blk_dev_init(void)
{
    BUILD_BUG_ON((__force u32)REQ_OP_LAST >= (1 << REQ_OP_BITS));
    BUILD_BUG_ON(REQ_OP_BITS + REQ_FLAG_BITS > 8 *
            sizeof_field(struct request, cmd_flags));
    BUILD_BUG_ON(REQ_OP_BITS + REQ_FLAG_BITS > 8 *
            sizeof_field(struct bio, bi_opf));

#if 0
    /* used for unplugging and affects IO latency/throughput - HIGHPRI */
    kblockd_workqueue = alloc_workqueue("kblockd",
                        WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
    if (!kblockd_workqueue)
        panic("Failed to create kblockd\n");
#endif

    blk_requestq_cachep = KMEM_CACHE(request_queue, SLAB_PANIC);

    //blk_debugfs_root = debugfs_create_dir("block", NULL);

    return 0;
}
