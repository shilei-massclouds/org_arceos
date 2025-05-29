#include <linux/printk.h>
#include <linux/string.h>
#include <linux/blk-mq.h>
#include <linux/blk_types.h>
#include <linux/bio.h>

#include "booter.h"

extern struct bio *cl_bio_alloc(unsigned int nr_iovecs);

extern struct gendisk *cl_disk;

int cl_read_block(int blk_nr, void *rbuf, int count)
{
    printk("read_block id[%d] count[%d] ...\n", blk_nr, count);

    /* Test virtio_blk disk. */
    if (cl_disk == NULL || cl_disk->queue == NULL) {
        booter_panic("cl_disk or its rq is NULL! check device_add_disk.");
    }
    const struct blk_mq_ops *mq_ops = cl_disk->queue->mq_ops;
    if (mq_ops == NULL) {
        booter_panic("mq_ops is NULL!");
    }

    struct blk_mq_hw_ctx hw_ctx;
    memset(&hw_ctx, 0, sizeof(hw_ctx));
    hw_ctx.queue = cl_disk->queue;
    hw_ctx.queue_num = 0;

    struct request rq;
    memset(&rq, 0, sizeof(rq));
    rq.nr_phys_segments = 1;
    rq.__sector = blk_nr;
    rq.ioprio = 0;
    rq.cmd_flags = REQ_OP_READ;

    rq.bio = cl_bio_alloc(1);
    rq.bio->bi_iter.bi_sector = rq.__sector;

    void *buf = alloc_pages_exact(4096, 0);
    /*
    {
        char*p = (char *)buf;
        printk("Block: %x, %x, %x, %x\n", p[0], p[1], p[2], p[3]);
    }
    */
    __bio_add_page(rq.bio, buf, 4096, 0);

    struct blk_mq_queue_data data;
    memset(&data, 0, sizeof(data));
    data.rq = &rq;
    data.last = true;

    printk("mq_ops->queue_rq ...\n");
    blk_status_t status = mq_ops->queue_rq(&hw_ctx, &data);
    printk("mq_ops->queue_rq status (%d)\n", status);

    //mq_ops->complete(&rq);

    memcpy(rbuf, buf, count);
    return 0;
}

int cl_write_block(int blk_nr, const void *wbuf, int count)
{
    printk("\nwrite_block id[%d] count[%d] ...\n", blk_nr, count);

    /* Test virtio_blk disk. */
    if (cl_disk == NULL || cl_disk->queue == NULL) {
        booter_panic("cl_disk or its rq is NULL! check device_add_disk.");
    }

    const struct blk_mq_ops *mq_ops = cl_disk->queue->mq_ops;
    if (mq_ops == NULL) {
        booter_panic("mq_ops is NULL!");
    }

    struct blk_mq_hw_ctx hw_ctx;
    memset(&hw_ctx, 0, sizeof(hw_ctx));
    hw_ctx.queue = cl_disk->queue;
    hw_ctx.queue_num = 0;

    struct request rq;
    memset(&rq, 0, sizeof(rq));
    rq.nr_phys_segments = 1;
    rq.__sector = blk_nr;
    rq.ioprio = 0;
    rq.cmd_flags = REQ_OP_WRITE;

    rq.bio = cl_bio_alloc(1);
    rq.bio->bi_iter.bi_sector = rq.__sector;

    void *buf = alloc_pages_exact(4096, 0);
    __bio_add_page(rq.bio, buf, 4096, 0);

    memcpy(buf, wbuf, count);

    struct blk_mq_queue_data data;
    memset(&data, 0, sizeof(data));
    data.rq = &rq;
    data.last = true;

    printk("mq_ops->queue_rq ...\n");
    blk_status_t status = mq_ops->queue_rq(&hw_ctx, &data);
    printk("mq_ops->queue_rq status (%d)\n", status);

    printk("write_block id[%d] count[%d] ok!\n\n", blk_nr, count);

    return 0;
}
