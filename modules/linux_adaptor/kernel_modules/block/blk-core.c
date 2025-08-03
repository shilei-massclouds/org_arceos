/*
 * This handles all read/write requests to block devices
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-pm.h>
#include <linux/blk-integrity.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/kernel_stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/fault-inject.h>
#include <linux/list_sort.h>
#include <linux/delay.h>
#include <linux/ratelimit.h>
#include <linux/pm_runtime.h>
#include <linux/t10-pi.h>
#include <linux/debugfs.h>
#include <linux/bpf.h>
#include <linux/part_stat.h>
#include <linux/sched/sysctl.h>
#include <linux/blk-crypto.h>

#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-pm.h"
#include "blk-cgroup.h"
#include "blk-throttle.h"
#include "blk-ioprio.h"

#include "../adaptor.h"

static DEFINE_IDA(blk_queue_ida);

/*
 * Controlling structure to kblockd
 */
static struct workqueue_struct *kblockd_workqueue;

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

static void bio_set_ioprio(struct bio *bio)
{
    /* Nobody set ioprio so far? Initialize it based on task's nice value */
    if (IOPRIO_PRIO_CLASS(bio->bi_ioprio) == IOPRIO_CLASS_NONE)
        bio->bi_ioprio = get_current_ioprio();
    blkcg_set_ioprio(bio);
}

static noinline int should_fail_bio(struct bio *bio)
{
    if (should_fail_request(bdev_whole(bio->bi_bdev), bio->bi_iter.bi_size))
        return -EIO;
    return 0;
}

static inline void bio_check_ro(struct bio *bio)
{
    if (op_is_write(bio_op(bio)) && bdev_read_only(bio->bi_bdev)) {
        if (op_is_flush(bio->bi_opf) && !bio_sectors(bio))
            return;

        if (bdev_test_flag(bio->bi_bdev, BD_RO_WARNED))
            return;

        bdev_set_flag(bio->bi_bdev, BD_RO_WARNED);

        /*
         * Use ioctl to set underlying disk of raid/dm to read-only
         * will trigger this.
         */
        pr_warn("Trying to write to read-only block-device %pg\n",
            bio->bi_bdev);
    }
}

/*
 * Check whether this bio extends beyond the end of the device or partition.
 * This may well happen - the kernel calls bread() without checking the size of
 * the device, e.g., when mounting a file system.
 */
static inline int bio_check_eod(struct bio *bio)
{
    sector_t maxsector = bdev_nr_sectors(bio->bi_bdev);
    unsigned int nr_sectors = bio_sectors(bio);

    if (nr_sectors &&
        (nr_sectors > maxsector ||
         bio->bi_iter.bi_sector > maxsector - nr_sectors)) {
        pr_info_ratelimited("%s: attempt to access beyond end of device\n"
                    "%pg: rw=%d, sector=%llu, nr_sectors = %u limit=%llu\n",
                    current->comm, bio->bi_bdev, bio->bi_opf,
                    bio->bi_iter.bi_sector, nr_sectors, maxsector);
        return -EIO;
    }
    return 0;
}

/*
 * Remap block n of partition p to block n+start(p) of the disk.
 */
static int blk_partition_remap(struct bio *bio)
{
    struct block_device *p = bio->bi_bdev;

    if (unlikely(should_fail_request(p, bio->bi_iter.bi_size)))
        return -EIO;
    if (bio_sectors(bio)) {
        bio->bi_iter.bi_sector += p->bd_start_sect;
        /*
        trace_block_bio_remap(bio, p->bd_dev,
                      bio->bi_iter.bi_sector -
                      p->bd_start_sect);
        */
    }
    bio_set_flag(bio, BIO_REMAPPED);
    return 0;
}

static blk_status_t blk_validate_atomic_write_op_size(struct request_queue *q,
                         struct bio *bio)
{
    if (bio->bi_iter.bi_size > queue_atomic_write_unit_max_bytes(q))
        return BLK_STS_INVAL;

    if (bio->bi_iter.bi_size % queue_atomic_write_unit_min_bytes(q))
        return BLK_STS_INVAL;

    return BLK_STS_OK;
}

/*
 * Check write append to a zoned block device.
 */
static inline blk_status_t blk_check_zone_append(struct request_queue *q,
                         struct bio *bio)
{
    int nr_sectors = bio_sectors(bio);

    /* Only applicable to zoned block devices */
    if (!bdev_is_zoned(bio->bi_bdev))
        return BLK_STS_NOTSUPP;

    /* The bio sector must point to the start of a sequential zone */
    if (!bdev_is_zone_start(bio->bi_bdev, bio->bi_iter.bi_sector))
        return BLK_STS_IOERR;

    /*
     * Not allowed to cross zone boundaries. Otherwise, the BIO will be
     * split and could result in non-contiguous sectors being written in
     * different zones.
     */
    if (nr_sectors > q->limits.chunk_sectors)
        return BLK_STS_IOERR;

    /* Make sure the BIO is small enough and will not get split */
    if (nr_sectors > queue_max_zone_append_sectors(q))
        return BLK_STS_IOERR;

    bio->bi_opf |= REQ_NOMERGE;

    return BLK_STS_OK;
}

/**
 * submit_bio_noacct - re-submit a bio to the block device layer for I/O
 * @bio:  The bio describing the location in memory and on the device.
 *
 * This is a version of submit_bio() that shall only be used for I/O that is
 * resubmitted to lower level drivers by stacking block drivers.  All file
 * systems and other upper level users of the block layer should use
 * submit_bio() instead.
 */
void submit_bio_noacct(struct bio *bio)
{
    struct block_device *bdev = bio->bi_bdev;
    struct request_queue *q = bdev_get_queue(bdev);
    blk_status_t status = BLK_STS_IOERR;

    might_sleep();

    /*
     * For a REQ_NOWAIT based request, return -EOPNOTSUPP
     * if queue does not support NOWAIT.
     */
    if ((bio->bi_opf & REQ_NOWAIT) && !bdev_nowait(bdev))
        goto not_supported;

    if (should_fail_bio(bio))
        goto end_io;
    bio_check_ro(bio);
    if (!bio_flagged(bio, BIO_REMAPPED)) {
        if (unlikely(bio_check_eod(bio)))
            goto end_io;
        if (bdev_is_partition(bdev) &&
            unlikely(blk_partition_remap(bio)))
            goto end_io;
    }

    /*
     * Filter flush bio's early so that bio based drivers without flush
     * support don't have to worry about them.
     */
    if (op_is_flush(bio->bi_opf)) {
        if (WARN_ON_ONCE(bio_op(bio) != REQ_OP_WRITE &&
                 bio_op(bio) != REQ_OP_ZONE_APPEND))
            goto end_io;
        if (!bdev_write_cache(bdev)) {
            bio->bi_opf &= ~(REQ_PREFLUSH | REQ_FUA);
            if (!bio_sectors(bio)) {
                status = BLK_STS_OK;
                goto end_io;
            }
        }
    }

    switch (bio_op(bio)) {
    case REQ_OP_READ:
        break;
    case REQ_OP_WRITE:
        if (bio->bi_opf & REQ_ATOMIC) {
            status = blk_validate_atomic_write_op_size(q, bio);
            if (status != BLK_STS_OK)
                goto end_io;
        }
        break;
    case REQ_OP_FLUSH:
        /*
         * REQ_OP_FLUSH can't be submitted through bios, it is only
         * synthetized in struct request by the flush state machine.
         */
        goto not_supported;
    case REQ_OP_DISCARD:
        if (!bdev_max_discard_sectors(bdev))
            goto not_supported;
        break;
    case REQ_OP_SECURE_ERASE:
        if (!bdev_max_secure_erase_sectors(bdev))
            goto not_supported;
        break;
    case REQ_OP_ZONE_APPEND:
        status = blk_check_zone_append(q, bio);
        if (status != BLK_STS_OK)
            goto end_io;
        break;
    case REQ_OP_WRITE_ZEROES:
        if (!q->limits.max_write_zeroes_sectors)
            goto not_supported;
        break;
    case REQ_OP_ZONE_RESET:
    case REQ_OP_ZONE_OPEN:
    case REQ_OP_ZONE_CLOSE:
    case REQ_OP_ZONE_FINISH:
    case REQ_OP_ZONE_RESET_ALL:
        if (!bdev_is_zoned(bio->bi_bdev))
            goto not_supported;
        break;
    case REQ_OP_DRV_IN:
    case REQ_OP_DRV_OUT:
        /*
         * Driver private operations are only used with passthrough
         * requests.
         */
        fallthrough;
    default:
        goto not_supported;
    }

    if (blk_throtl_bio(bio))
        return;
    submit_bio_noacct_nocheck(bio);
    return;

not_supported:
    status = BLK_STS_NOTSUPP;
end_io:
    bio->bi_status = status;
    bio_endio(bio);
    PANIC("ERR");
}

void blk_queue_exit(struct request_queue *q)
{
    pr_err("%s: No impl", __func__);
    //percpu_ref_put(&q->q_usage_counter);
}

int __bio_queue_enter(struct request_queue *q, struct bio *bio)
{
#if 0
    while (!blk_try_enter_queue(q, false)) {
        struct gendisk *disk = bio->bi_bdev->bd_disk;

        if (bio->bi_opf & REQ_NOWAIT) {
            if (test_bit(GD_DEAD, &disk->state))
                goto dead;
            bio_wouldblock_error(bio);
            return -EAGAIN;
        }

        /*
         * read pair of barrier in blk_freeze_queue_start(), we need to
         * order reading __PERCPU_REF_DEAD flag of .q_usage_counter and
         * reading .mq_freeze_depth or queue dying flag, otherwise the
         * following wait may never return if the two reads are
         * reordered.
         */
        smp_rmb();
        wait_event(q->mq_freeze_wq,
               (!q->mq_freeze_depth &&
                blk_pm_resume_queue(false, q)) ||
               test_bit(GD_DEAD, &disk->state));
        if (test_bit(GD_DEAD, &disk->state))
            goto dead;
    }

    rwsem_acquire_read(&q->io_lockdep_map, 0, 0, _RET_IP_);
    rwsem_release(&q->io_lockdep_map, _RET_IP_);
    return 0;
dead:
    bio_io_error(bio);
    return -ENODEV;
#endif
    PANIC("");
}

static void __submit_bio(struct bio *bio)
{
    /* If plug is not used, add new plug here to cache nsecs time. */
    struct blk_plug plug;

    if (unlikely(!blk_crypto_bio_prep(&bio)))
        return;

    blk_start_plug(&plug);

    if (!bdev_test_flag(bio->bi_bdev, BD_HAS_SUBMIT_BIO)) {
        blk_mq_submit_bio(bio);
    } else if (likely(bio_queue_enter(bio) == 0)) {
        PANIC("2");
#if 0
        struct gendisk *disk = bio->bi_bdev->bd_disk;

        if ((bio->bi_opf & REQ_POLLED) &&
            !(disk->queue->limits.features & BLK_FEAT_POLL)) {
            bio->bi_status = BLK_STS_NOTSUPP;
            bio_endio(bio);
        } else {
            disk->fops->submit_bio(bio);
        }
        blk_queue_exit(disk->queue);
#endif
    }

    blk_finish_plug(&plug);
}

/**
 * blk_finish_plug - mark the end of a batch of submitted I/O
 * @plug:   The &struct blk_plug passed to blk_start_plug()
 *
 * Description:
 * Indicate that a batch of I/O submissions is complete.  This function
 * must be paired with an initial call to blk_start_plug().  The intent
 * is to allow the block layer to optimize I/O submission.  See the
 * documentation for blk_start_plug() for more information.
 */
void blk_finish_plug(struct blk_plug *plug)
{
    if (plug == current->plug) {
        __blk_flush_plug(plug, false);
        current->plug = NULL;
    }
}

static void flush_plug_callbacks(struct blk_plug *plug, bool from_schedule)
{
    LIST_HEAD(callbacks);

    while (!list_empty(&plug->cb_list)) {
        list_splice_init(&plug->cb_list, &callbacks);

        while (!list_empty(&callbacks)) {
            struct blk_plug_cb *cb = list_first_entry(&callbacks,
                              struct blk_plug_cb,
                              list);
            list_del(&cb->list);
            cb->callback(cb, from_schedule);
        }
    }
}

void __blk_flush_plug(struct blk_plug *plug, bool from_schedule)
{
    if (!list_empty(&plug->cb_list))
        flush_plug_callbacks(plug, from_schedule);
    blk_mq_flush_plug_list(plug, from_schedule);
    /*
     * Unconditionally flush out cached requests, even if the unplug
     * event came from schedule. Since we know hold references to the
     * queue for cached requests, we don't want a blocked task holding
     * up a queue freeze/quiesce event.
     */
    if (unlikely(!rq_list_empty(&plug->cached_rqs)))
        blk_mq_free_plug_rqs(plug);

    plug->cur_ktime = 0;
    current->flags &= ~PF_BLOCK_TS;
}

void update_io_ticks(struct block_device *part, unsigned long now, bool end)
{
    unsigned long stamp;
again:
    stamp = READ_ONCE(part->bd_stamp);
    if (unlikely(time_after(now, stamp)) &&
        likely(try_cmpxchg(&part->bd_stamp, &stamp, now)) &&
        (end || part_in_flight(part)))
        __part_stat_add(part, io_ticks, now - stamp);

    if (bdev_is_partition(part)) {
        part = bdev_whole(part);
        goto again;
    }
}

/**
 * blk_start_plug - initialize blk_plug and track it inside the task_struct
 * @plug:   The &struct blk_plug that needs to be initialized
 *
 * Description:
 *   blk_start_plug() indicates to the block layer an intent by the caller
 *   to submit multiple I/O requests in a batch.  The block layer may use
 *   this hint to defer submitting I/Os from the caller until blk_finish_plug()
 *   is called.  However, the block layer may choose to submit requests
 *   before a call to blk_finish_plug() if the number of queued I/Os
 *   exceeds %BLK_MAX_REQUEST_COUNT, or if the size of the I/O is larger than
 *   %BLK_PLUG_FLUSH_SIZE.  The queued I/Os may also be submitted early if
 *   the task schedules (see below).
 *
 *   Tracking blk_plug inside the task_struct will help with auto-flushing the
 *   pending I/O should the task end up blocking between blk_start_plug() and
 *   blk_finish_plug(). This is important from a performance perspective, but
 *   also ensures that we don't deadlock. For instance, if the task is blocking
 *   for a memory allocation, memory reclaim could end up wanting to free a
 *   page belonging to that request that is currently residing in our private
 *   plug. By flushing the pending I/O when the process goes to sleep, we avoid
 *   this kind of deadlock.
 */
void blk_start_plug(struct blk_plug *plug)
{
    blk_start_plug_nr_ios(plug, 1);
}

void blk_start_plug_nr_ios(struct blk_plug *plug, unsigned short nr_ios)
{
    struct task_struct *tsk = current;

    /*
     * If this is a nested plug, don't actually assign it.
     */
    if (tsk->plug)
        return;

    plug->cur_ktime = 0;
    rq_list_init(&plug->mq_list);
    rq_list_init(&plug->cached_rqs);
    plug->nr_ios = min_t(unsigned short, nr_ios, BLK_MAX_REQUEST_COUNT);
    plug->rq_count = 0;
    plug->multiple_queues = false;
    plug->has_elevator = false;
    INIT_LIST_HEAD(&plug->cb_list);

    /*
     * Store ordering should not be needed here, since a potential
     * preempt will imply a full memory barrier
     */
    tsk->plug = plug;
}

int kblockd_mod_delayed_work_on(int cpu, struct delayed_work *dwork,
                unsigned long delay)
{
    return mod_delayed_work_on(cpu, kblockd_workqueue, dwork, delay);
}

static void __submit_bio_noacct_mq(struct bio *bio)
{
    struct bio_list bio_list[2] = { };

    current->bio_list = bio_list;

    do {
        __submit_bio(bio);
    } while ((bio = bio_list_pop(&bio_list[0])));

    current->bio_list = NULL;
}

/*
 * The loop in this function may be a bit non-obvious, and so deserves some
 * explanation:
 *
 *  - Before entering the loop, bio->bi_next is NULL (as all callers ensure
 *    that), so we have a list with a single bio.
 *  - We pretend that we have just taken it off a longer list, so we assign
 *    bio_list to a pointer to the bio_list_on_stack, thus initialising the
 *    bio_list of new bios to be added.  ->submit_bio() may indeed add some more
 *    bios through a recursive call to submit_bio_noacct.  If it did, we find a
 *    non-NULL value in bio_list and re-enter the loop from the top.
 *  - In this case we really did just take the bio of the top of the list (no
 *    pretending) and so remove it from bio_list, and call into ->submit_bio()
 *    again.
 *
 * bio_list_on_stack[0] contains bios submitted by the current ->submit_bio.
 * bio_list_on_stack[1] contains bios that were submitted before the current
 *  ->submit_bio, but that haven't been processed yet.
 */
static void __submit_bio_noacct(struct bio *bio)
{
    PANIC("");
}

void submit_bio_noacct_nocheck(struct bio *bio)
{
    //blk_cgroup_bio_start(bio);
    blkcg_bio_issue_init(bio);

    if (!bio_flagged(bio, BIO_TRACE_COMPLETION)) {
        //trace_block_bio_queue(bio);
        /*
         * Now that enqueuing has been traced, we need to trace
         * completion as well.
         */
        bio_set_flag(bio, BIO_TRACE_COMPLETION);
    }

    /*
     * We only want one ->submit_bio to be active at a time, else stack
     * usage with stacked devices could be a problem.  Use current->bio_list
     * to collect a list of requests submited by a ->submit_bio method while
     * it is active, and then process them after it returned.
     */
    if (current->bio_list)
        bio_list_add(&current->bio_list[0], bio);
    else if (!bdev_test_flag(bio->bi_bdev, BD_HAS_SUBMIT_BIO))
        __submit_bio_noacct_mq(bio);
    else
        __submit_bio_noacct(bio);
}

/**
 * submit_bio - submit a bio to the block device layer for I/O
 * @bio: The &struct bio which describes the I/O
 *
 * submit_bio() is used to submit I/O requests to block devices.  It is passed a
 * fully set up &struct bio that describes the I/O that needs to be done.  The
 * bio will be send to the device described by the bi_bdev field.
 *
 * The success/failure status of the request, along with notification of
 * completion, is delivered asynchronously through the ->bi_end_io() callback
 * in @bio.  The bio must NOT be touched by the caller until ->bi_end_io() has
 * been called.
 */
void submit_bio(struct bio *bio)
{
    if (bio_op(bio) == REQ_OP_READ) {
        task_io_account_read(bio->bi_iter.bi_size);
        //count_vm_events(PGPGIN, bio_sectors(bio));
    } else if (bio_op(bio) == REQ_OP_WRITE) {
        //count_vm_events(PGPGOUT, bio_sectors(bio));
    }

    bio_set_ioprio(bio);
    submit_bio_noacct(bio);
}

int __init blk_dev_init(void)
{
    BUILD_BUG_ON((__force u32)REQ_OP_LAST >= (1 << REQ_OP_BITS));
    BUILD_BUG_ON(REQ_OP_BITS + REQ_FLAG_BITS > 8 *
            sizeof_field(struct request, cmd_flags));
    BUILD_BUG_ON(REQ_OP_BITS + REQ_FLAG_BITS > 8 *
            sizeof_field(struct bio, bi_opf));

    /* used for unplugging and affects IO latency/throughput - HIGHPRI */
    kblockd_workqueue = alloc_workqueue("kblockd",
                        WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
    if (!kblockd_workqueue)
        panic("Failed to create kblockd\n");

    blk_requestq_cachep = KMEM_CACHE(request_queue, SLAB_PANIC);

    //blk_debugfs_root = debugfs_create_dir("block", NULL);

    return 0;
}
