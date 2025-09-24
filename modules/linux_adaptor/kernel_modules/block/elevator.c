#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/blktrace_api.h>
#include <linux/hash.h>
#include <linux/uaccess.h>
#include <linux/pm_runtime.h>

#include <trace/events/block.h>

#include "elevator.h"
#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-pm.h"
#include "blk-wbt.h"
#include "blk-cgroup.h"

static DEFINE_SPINLOCK(elv_list_lock);
static LIST_HEAD(elv_list);

/*
 * Merge hash stuff.
 */
#define rq_hash_key(rq)     (blk_rq_pos(rq) + blk_rq_sectors(rq))

/**
 * elevator_match - Check whether @e's name or alias matches @name
 * @e: Scheduler to test
 * @name: Elevator name to test
 *
 * Return true if the elevator @e's name or alias matches @name.
 */
static bool elevator_match(const struct elevator_type *e, const char *name)
{
    return !strcmp(e->elevator_name, name) ||
        (e->elevator_alias && !strcmp(e->elevator_alias, name));
}

static struct elevator_type *__elevator_find(const char *name)
{
    struct elevator_type *e;

    list_for_each_entry(e, &elv_list, list)
        if (elevator_match(e, name))
            return e;
    return NULL;
}

static struct elevator_type *elevator_find_get(const char *name)
{
    struct elevator_type *e;

    spin_lock(&elv_list_lock);
    e = __elevator_find(name);
    if (e && (!elevator_tryget(e)))
        e = NULL;
    spin_unlock(&elv_list_lock);
    return e;
}

static const struct kobj_type elv_ktype;

struct elevator_queue *elevator_alloc(struct request_queue *q,
                  struct elevator_type *e)
{
    struct elevator_queue *eq;

    eq = kzalloc_node(sizeof(*eq), GFP_KERNEL, q->node);
    if (unlikely(!eq))
        return NULL;

    __elevator_get(e);
    eq->type = e;
    kobject_init(&eq->kobj, &elv_ktype);
    mutex_init(&eq->sysfs_lock);
    hash_init(eq->hash);

    return eq;
}

static inline bool elv_support_iosched(struct request_queue *q)
{
    if (!queue_is_mq(q) ||
        (q->tag_set->flags & BLK_MQ_F_NO_SCHED))
        return false;
    return true;
}

/*
 * For single queue devices, default to using mq-deadline. If we have multiple
 * queues or mq-deadline is not available, default to "none".
 */
static struct elevator_type *elevator_get_default(struct request_queue *q)
{
    if (q->tag_set->flags & BLK_MQ_F_NO_SCHED_BY_DEFAULT)
        return NULL;

    if (q->nr_hw_queues != 1 &&
        !blk_mq_is_shared_tags(q->tag_set->flags))
        return NULL;

    return elevator_find_get("mq-deadline");
}

/*
 * Use the default elevator settings. If the chosen elevator initialization
 * fails, fall back to the "none" elevator (no elevator).
 */
void elevator_init_mq(struct request_queue *q)
{
    struct elevator_type *e;
    int err;

    if (!elv_support_iosched(q))
        return;

    WARN_ON_ONCE(blk_queue_registered(q));

    if (unlikely(q->elevator))
        return;

    e = elevator_get_default(q);
    if (!e)
        return;

    /*
     * We are called before adding disk, when there isn't any FS I/O,
     * so freezing queue plus canceling dispatch work is enough to
     * drain any dispatch activities originated from passthrough
     * requests, then no need to quiesce queue which may add long boot
     * latency, especially when lots of disks are involved.
     *
     * Disk isn't added yet, so verifying queue lock only manually.
     */
    blk_freeze_queue_start_non_owner(q);
    blk_freeze_acquire_lock(q, true, false);
    blk_mq_freeze_queue_wait(q);

    blk_mq_cancel_work_sync(q);

    err = blk_mq_init_sched(q, e);

    blk_unfreeze_release_lock(q, true, false);
    blk_mq_unfreeze_queue_non_owner(q);

    if (err) {
        pr_warn("\"%s\" elevator initialization failed, "
            "falling back to \"none\"\n", e->elevator_name);
    }

    elevator_put(e);
}

int elv_register(struct elevator_type *e)
{
    /* finish request is mandatory */
    if (WARN_ON_ONCE(!e->ops.finish_request))
        return -EINVAL;
    /* insert_requests and dispatch_request are mandatory */
    if (WARN_ON_ONCE(!e->ops.insert_requests || !e->ops.dispatch_request))
        return -EINVAL;

    /* create icq_cache if requested */
    if (e->icq_size) {
        if (WARN_ON(e->icq_size < sizeof(struct io_cq)) ||
            WARN_ON(e->icq_align < __alignof__(struct io_cq)))
            return -EINVAL;

        snprintf(e->icq_cache_name, sizeof(e->icq_cache_name),
             "%s_io_cq", e->elevator_name);
        e->icq_cache = kmem_cache_create(e->icq_cache_name, e->icq_size,
                         e->icq_align, 0, NULL);
        if (!e->icq_cache)
            return -ENOMEM;
    }

    /* register, don't allow duplicate names */
    spin_lock(&elv_list_lock);
    if (__elevator_find(e->elevator_name)) {
        spin_unlock(&elv_list_lock);
        kmem_cache_destroy(e->icq_cache);
        return -EBUSY;
    }
    list_add_tail(&e->list, &elv_list);
    spin_unlock(&elv_list_lock);

    printk(KERN_INFO "io scheduler %s registered\n", e->elevator_name);

    return 0;
}

static inline void __elv_rqhash_del(struct request *rq)
{
    hash_del(&rq->hash);
    rq->rq_flags &= ~RQF_HASHED;
}

void elv_rqhash_del(struct request_queue *q, struct request *rq)
{
    if (ELV_ON_HASH(rq))
        __elv_rqhash_del(rq);
}

struct request *elv_rqhash_find(struct request_queue *q, sector_t offset)
{
    struct elevator_queue *e = q->elevator;
    struct hlist_node *next;
    struct request *rq;

    hash_for_each_possible_safe(e->hash, rq, next, hash, offset) {
        BUG_ON(!ELV_ON_HASH(rq));

        if (unlikely(!rq_mergeable(rq))) {
            __elv_rqhash_del(rq);
            continue;
        }

        if (rq_hash_key(rq) == offset)
            return rq;
    }

    return NULL;
}

enum elv_merge elv_merge(struct request_queue *q, struct request **req,
        struct bio *bio)
{
    struct elevator_queue *e = q->elevator;
    struct request *__rq;

    /*
     * Levels of merges:
     *  nomerges:  No merges at all attempted
     *  noxmerges: Only simple one-hit cache try
     *  merges:    All merge tries attempted
     */
    if (blk_queue_nomerges(q) || !bio_mergeable(bio))
        return ELEVATOR_NO_MERGE;

    /*
     * First try one-hit cache.
     */
    if (q->last_merge && elv_bio_merge_ok(q->last_merge, bio)) {
        enum elv_merge ret = blk_try_merge(q->last_merge, bio);

        if (ret != ELEVATOR_NO_MERGE) {
            *req = q->last_merge;
            return ret;
        }
    }

    if (blk_queue_noxmerges(q))
        return ELEVATOR_NO_MERGE;

    /*
     * See if our hash lookup can find a potential backmerge.
     */
    __rq = elv_rqhash_find(q, bio->bi_iter.bi_sector);
    if (__rq && elv_bio_merge_ok(__rq, bio)) {
        *req = __rq;

        if (blk_discard_mergable(__rq))
            return ELEVATOR_DISCARD_MERGE;
        return ELEVATOR_BACK_MERGE;
    }

    if (e->type->ops.request_merge)
        return e->type->ops.request_merge(q, req, bio);

    return ELEVATOR_NO_MERGE;
}

struct request *elv_rb_find(struct rb_root *root, sector_t sector)
{
    struct rb_node *n = root->rb_node;
    struct request *rq;

    while (n) {
        rq = rb_entry(n, struct request, rb_node);

        if (sector < blk_rq_pos(rq))
            n = n->rb_left;
        else if (sector > blk_rq_pos(rq))
            n = n->rb_right;
        else
            return rq;
    }

    return NULL;
}

/*
 * Attempt to do an insertion back merge. Only check for the case where
 * we can append 'rq' to an existing request, so we can throw 'rq' away
 * afterwards.
 *
 * Returns true if we merged, false otherwise. 'free' will contain all
 * requests that need to be freed.
 */
bool elv_attempt_insert_merge(struct request_queue *q, struct request *rq,
                  struct list_head *free)
{
    struct request *__rq;
    bool ret;

    if (blk_queue_nomerges(q))
        return false;

    /*
     * First try one-hit cache.
     */
    if (q->last_merge && blk_attempt_req_merge(q, q->last_merge, rq)) {
        list_add(&rq->queuelist, free);
        return true;
    }

    if (blk_queue_noxmerges(q))
        return false;

    ret = false;
    /*
     * See if our hash lookup can find a potential backmerge.
     */
    while (1) {
        __rq = elv_rqhash_find(q, blk_rq_pos(rq));
        if (!__rq || !blk_attempt_req_merge(q, __rq, rq))
            break;

        list_add(&rq->queuelist, free);
        /* The merged request could be merged with others, try again */
        ret = true;
        rq = __rq;
    }

    return ret;
}

/*
 * RB-tree support functions for inserting/lookup/removal of requests
 * in a sorted RB tree.
 */
void elv_rb_add(struct rb_root *root, struct request *rq)
{
    struct rb_node **p = &root->rb_node;
    struct rb_node *parent = NULL;
    struct request *__rq;

    while (*p) {
        parent = *p;
        __rq = rb_entry(parent, struct request, rb_node);

        if (blk_rq_pos(rq) < blk_rq_pos(__rq))
            p = &(*p)->rb_left;
        else if (blk_rq_pos(rq) >= blk_rq_pos(__rq))
            p = &(*p)->rb_right;
    }

    rb_link_node(&rq->rb_node, parent, p);
    rb_insert_color(&rq->rb_node, root);
}

void elv_rb_del(struct rb_root *root, struct request *rq)
{
    BUG_ON(RB_EMPTY_NODE(&rq->rb_node));
    rb_erase(&rq->rb_node, root);
    RB_CLEAR_NODE(&rq->rb_node);
}

void elv_rqhash_add(struct request_queue *q, struct request *rq)
{
    struct elevator_queue *e = q->elevator;

    BUG_ON(ELV_ON_HASH(rq));
    hash_add(e->hash, &rq->hash, rq_hash_key(rq));
    rq->rq_flags |= RQF_HASHED;
}
