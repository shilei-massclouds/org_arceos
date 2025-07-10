#include <linux/gfp.h>
#include <linux/bio.h>

/**
 * blkdev_issue_flush - queue a flush
 * @bdev:   blockdev to issue flush for
 * @gfp_mask:   memory allocation flags (for bio_alloc)
 *
 * Description:
 *    Issue a flush for the block device in question.
 */
int blkdev_issue_flush(struct block_device *bdev, gfp_t gfp_mask)
{
    struct bio *bio;
    int ret = 0;

    printk("%s: ...\n", __func__);
    bio = bio_alloc(gfp_mask, 0);
    bio_set_dev(bio, bdev);
    bio->bi_opf = REQ_OP_WRITE | REQ_PREFLUSH;

    ret = submit_bio_wait(bio);
    bio_put(bio);
    return ret;
}
