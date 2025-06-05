#include <linux/types.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/blk-mq.h>
#include <linux/backing-dev.h>

#include "booter.h"
#include "blk-wbt.h"

extern struct gendisk *cl_disk;

static unsigned blk_bvec_map_sg(struct request_queue *q,
        struct bio_vec *bvec, struct scatterlist *sglist,
        struct scatterlist **sg)
{
    booter_panic("No impl.");
}

int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set)
{
    printk("%s: NOTE: ---> Impl it.\n", __func__);
    return 0;
}

void blk_queue_flag_set(unsigned int flag, struct request_queue *q)
{
    set_bit(flag, &q->queue_flags);
}

void blk_queue_flag_clear(unsigned int flag, struct request_queue *q)
{
    clear_bit(flag, &q->queue_flags);
}

int revalidate_disk(struct gendisk *disk)
{
    printk("%s: impl it.\n", __func__);
    return 0;
}

struct request_queue *blk_alloc_queue(int node_id)
{
    struct request_queue *q;
    int ret;

    //q = kmem_cache_alloc_node(blk_requestq_cachep,
    //            GFP_KERNEL | __GFP_ZERO, node_id);
    q = kmalloc_node(sizeof(struct request_queue),
                     GFP_KERNEL | __GFP_ZERO, node_id);
    if (!q)
        return NULL;

    q->last_merge = NULL;

    /*
    q->id = ida_simple_get(&blk_queue_ida, 0, 0, GFP_KERNEL);
    if (q->id < 0) {
        booter_panic("blk_alloc_queue error!");
    }

    ret = bioset_init(&q->bio_split, BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
    if (ret) {
        booter_panic("blk_alloc_queue error!");
    }
    */

    q->backing_dev_info = bdi_alloc(node_id);
    if (!q->backing_dev_info) {
        booter_panic("blk_alloc_queue error!");
    }

    /*
    q->stats = blk_alloc_queue_stats();
    if (!q->stats) {
        booter_panic("blk_alloc_queue error!");
    }
    */

    q->backing_dev_info->ra_pages = VM_READAHEAD_PAGES;
    q->backing_dev_info->io_pages = VM_READAHEAD_PAGES;
    q->backing_dev_info->capabilities = BDI_CAP_CGROUP_WRITEBACK;
    q->node = node_id;

    /*
    timer_setup(&q->backing_dev_info->laptop_mode_wb_timer,
            laptop_mode_timer_fn, 0);
            */
    //timer_setup(&q->timeout, blk_rq_timed_out_timer, 0);
    //INIT_WORK(&q->timeout_work, blk_timeout_work);
    INIT_LIST_HEAD(&q->icq_list);
#ifdef CONFIG_BLK_CGROUP
    INIT_LIST_HEAD(&q->blkg_list);
#endif

    //kobject_init(&q->kobj, &blk_queue_ktype);

    mutex_init(&q->debugfs_mutex);
    mutex_init(&q->sysfs_lock);
    mutex_init(&q->sysfs_dir_lock);
    spin_lock_init(&q->queue_lock);

    //init_waitqueue_head(&q->mq_freeze_wq);
    mutex_init(&q->mq_freeze_lock);

//    /*
//     * Init percpu_ref in atomic mode so that it's faster to shutdown.
//     * See blk_register_queue() for details.
//     */
//    if (percpu_ref_init(&q->q_usage_counter,
//                blk_queue_usage_counter_release,
//                PERCPU_REF_INIT_ATOMIC, GFP_KERNEL)) {
//        booter_panic("blk_alloc_queue error!");
//    }
//
//    if (blkcg_init_queue(q)) {
//        booter_panic("blk_alloc_queue error!");
//    }

    //blk_queue_dma_alignment(q, 511);
    //blk_set_default_limits(&q->limits);
    q->nr_requests = BLKDEV_MAX_RQ;

    printk("%s: impl it.\n", __func__);
    return q;
}

struct request_queue *blk_mq_init_queue_data(struct blk_mq_tag_set *set,
        void *queuedata)
{
    struct request_queue *uninit_q, *q;

    uninit_q = blk_alloc_queue(set->numa_node);
    if (!uninit_q)
        return ERR_PTR(-ENOMEM);
    uninit_q->queuedata = queuedata;

    /* mark the queue as mq asap */
    uninit_q->mq_ops = set->ops;

    printk("%s: impl it.\n", __func__);
    return uninit_q;
}

struct request_queue *blk_mq_init_queue(struct blk_mq_tag_set *set)
{
    return blk_mq_init_queue_data(set, NULL);
}

/**
 * blk_queue_write_cache - configure queue's write cache
 * @q:      the request queue for the device
 * @wc:     write back cache on or off
 * @fua:    device supports FUA writes, if true
 *
 * Tell the block layer about the write cache of @q.
 */
void blk_queue_write_cache(struct request_queue *q, bool wc, bool fua)
{
    if (wc)
        blk_queue_flag_set(QUEUE_FLAG_WC, q);
    else
        blk_queue_flag_clear(QUEUE_FLAG_WC, q);
    if (fua)
        blk_queue_flag_set(QUEUE_FLAG_FUA, q);
    else
        blk_queue_flag_clear(QUEUE_FLAG_FUA, q);

    wbt_set_write_cache(q, test_bit(QUEUE_FLAG_WC, &q->queue_flags));
}

struct backing_dev_info *bdi_alloc(int node_id)
{
    struct backing_dev_info *bdi;

    bdi = kzalloc_node(sizeof(*bdi), GFP_KERNEL, node_id);
    if (!bdi)
        return NULL;

    /*
    if (bdi_init(bdi)) {
        kfree(bdi);
        return NULL;
    }
    */
    printk("%s: No bdi_init.\n", __func__);
    return bdi;
}

void blk_queue_max_segments(struct request_queue *q, unsigned short max_segments)
{
    if (!max_segments) {
        max_segments = 1;
        printk(KERN_INFO "%s: set to minimum %d\n",
               __func__, max_segments);
    }

    q->limits.max_segments = max_segments;
}

void blk_queue_max_hw_sectors(struct request_queue *q, unsigned int max_hw_sectors)
{
    struct queue_limits *limits = &q->limits;
    unsigned int max_sectors;

    if ((max_hw_sectors << 9) < PAGE_SIZE) {
        max_hw_sectors = 1 << (PAGE_SHIFT - 9);
        printk(KERN_INFO "%s: set to minimum %d\n",
               __func__, max_hw_sectors);
    }

    limits->max_hw_sectors = max_hw_sectors;
    max_sectors = min_not_zero(max_hw_sectors, limits->max_dev_sectors);
    max_sectors = min_t(unsigned int, max_sectors, BLK_DEF_MAX_SECTORS);
    limits->max_sectors = max_sectors;
    q->backing_dev_info->io_pages = max_sectors >> (PAGE_SHIFT - 9);
}

/**
 * blk_queue_max_segment_size - set max segment size for blk_rq_map_sg
 * @q:  the request queue for the device
 * @max_size:  max size of segment in bytes
 *
 * Description:
 *    Enables a low level driver to set an upper limit on the size of a
 *    coalesced segment
 **/
void blk_queue_max_segment_size(struct request_queue *q, unsigned int max_size)
{
    if (max_size < PAGE_SIZE) {
        max_size = PAGE_SIZE;
        printk(KERN_INFO "%s: set to minimum %d\n",
               __func__, max_size);
    }

    /* see blk_queue_virt_boundary() for the explanation */
    WARN_ON_ONCE(q->limits.virt_boundary_mask);

    q->limits.max_segment_size = max_size;
}

void blk_queue_logical_block_size(struct request_queue *q, unsigned int size)
{
    q->limits.logical_block_size = size;

    if (q->limits.physical_block_size < size)
        q->limits.physical_block_size = size;

    if (q->limits.io_min < q->limits.physical_block_size)
        q->limits.io_min = q->limits.physical_block_size;
    printk("%s: ... size(%x)\n", __func__, size);
}

void blk_queue_max_discard_sectors(struct request_queue *q,
        unsigned int max_discard_sectors)
{
    q->limits.max_hw_discard_sectors = max_discard_sectors;
    q->limits.max_discard_sectors = max_discard_sectors;
    printk("%s: %x\n", __func__, max_discard_sectors);
}

void blk_queue_max_discard_segments(struct request_queue *q,
        unsigned short max_segments)
{
    q->limits.max_discard_segments = max_segments;
}

void blk_queue_max_write_zeroes_sectors(struct request_queue *q,
        unsigned int max_write_zeroes_sectors)
{
    q->limits.max_write_zeroes_sectors = max_write_zeroes_sectors;
}

void set_capacity_revalidate_and_notify(struct gendisk *disk, sector_t size,
                    bool revalidate)
{
    sector_t capacity = get_capacity(disk);

    set_capacity(disk, size);

    if (revalidate)
        revalidate_disk(disk);

    if (capacity != size && capacity != 0 && size != 0) {
        char *envp[] = { "RESIZE=1", NULL };

        booter_panic("No impl for 'kobject_uevent_env'.");
        //kobject_uevent_env(&disk_to_dev(disk)->kobj, KOBJ_CHANGE, envp);
    }
}

void blk_mq_start_request(struct request *rq)
{
    printk("%s: No impl.\n", __func__);
}

static inline struct scatterlist *blk_next_sg(struct scatterlist **sg,
        struct scatterlist *sglist)
{
    if (!*sg)
        return sglist;

    /*
     * If the driver previously mapped a shorter list, we could see a
     * termination bit prematurely unless it fully inits the sg table
     * on each mapping. We KNOW that there must be more entries here
     * or the driver would be buggy, so force clear the termination bit
     * to avoid doing a full sg_init_table() in drivers for each command.
     */
    sg_unmark_end(*sg);
    return sg_next(*sg);
}

static inline int __blk_bvec_map_sg(struct bio_vec bv,
        struct scatterlist *sglist, struct scatterlist **sg)
{
    *sg = blk_next_sg(sg, sglist);
    sg_set_page(*sg, bv.bv_page, bv.bv_len, bv.bv_offset);
    return 1;
}

static int __blk_bios_map_sg(struct request_queue *q, struct bio *bio,
                 struct scatterlist *sglist,
                 struct scatterlist **sg)
{
    int nsegs = 0;
    struct bio_vec bvec;
    struct bvec_iter iter;

    for_each_bio(bio) {
        printk("%s: bio \n", __func__);
        bio_for_each_bvec(bvec, bio, iter) {
            printk("%s: bvec (0x%lx) len(%u) offset(%u)\n",
                   __func__, (unsigned long)bvec.bv_page, bvec.bv_len, bvec.bv_offset);
        }

        if (bvec.bv_offset + bvec.bv_len <= PAGE_SIZE)
            nsegs += __blk_bvec_map_sg(bvec, sglist, sg);
        else
            nsegs += blk_bvec_map_sg(q, &bvec, sglist, sg);
    }

    return nsegs;
}

int __blk_rq_map_sg(struct request_queue *q, struct request *rq,
        struct scatterlist *sglist, struct scatterlist **last_sg)
{
    int nsegs = 0;

    printk("%s: ...\n", __func__);
    if (rq->rq_flags & RQF_SPECIAL_PAYLOAD)
        nsegs = __blk_bvec_map_sg(rq->special_vec, sglist, last_sg);
    else if (rq->bio && bio_op(rq->bio) == REQ_OP_WRITE_SAME)
        nsegs = __blk_bvec_map_sg(bio_iovec(rq->bio), sglist, last_sg);
    else if (rq->bio) {
        nsegs = __blk_bios_map_sg(q, rq->bio, sglist, last_sg);
        printk("%s: nsegs(%d)\n", __func__, nsegs);
    }

    if (*last_sg) {
        sg_mark_end(*last_sg);
        printk("%s: last_sg blk_rq_nr_phys_segments(%d)\n",
               __func__, blk_rq_nr_phys_segments(rq));
    }

    /*
     * Something must have been wrong if the figured number of
     * segment is bigger than number of req's physical segments
     */
    WARN_ON(nsegs > blk_rq_nr_phys_segments(rq));

    return nsegs;
}

void blk_mq_complete_request(struct request *rq)
{
    printk("%s: ...\n", __func__);

    /* From blk_mq_complete_request_remote */
    WRITE_ONCE(rq->state, MQ_RQ_COMPLETE);

    const struct blk_mq_ops *mq_ops = cl_disk->queue->mq_ops;
    if (mq_ops == NULL) {
        booter_panic("mq_ops is NULL!");
    }
    mq_ops->complete(rq);
}

void blk_mq_start_stopped_hw_queues(struct request_queue *q, bool async)
{
    printk("%s: No impl.\n", __func__);
}

void blk_mq_end_request(struct request *rq, blk_status_t error)
{
    printk("%s: blk_status_t(%d)\n", __func__, error);
    if (error != 0) {
        booter_panic("bad request!");
    }
}
