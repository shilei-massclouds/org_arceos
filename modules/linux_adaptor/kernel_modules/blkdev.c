#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>

#include "booter.h"

int sb_min_blocksize(struct super_block *sb, int size)
{
    return BLOCK_SIZE;
}

void __brelse(struct buffer_head * buf)
{
    if (atomic_read(&buf->b_count)) {
        put_bh(buf);
        return;
    }
    WARN(1, KERN_ERR "VFS: brelse: Trying to free free buffer\n");
}

int __sync_blockdev(struct block_device *bdev, int wait)
{
#if 0
    if (!bdev)
        return 0;
    if (!wait)
        return filemap_flush(bdev->bd_inode->i_mapping);
    return filemap_write_and_wait(bdev->bd_inode->i_mapping);
#endif
    booter_panic("No impl.");
}

/*
 * Write out and wait upon all the dirty data associated with a block
 * device via its mapping.  Does not take the superblock lock.
 */
int sync_blockdev(struct block_device *bdev)
{
    return __sync_blockdev(bdev, 1);
}

void blk_start_plug(struct blk_plug *plug)
{
    log_debug("%s: impl it.\n", __func__);
}

void blk_finish_plug(struct blk_plug *plug)
{
    log_debug("%s: impl it.\n", __func__);
}

static void end_bio_bh_io_sync(struct bio *bio)
{
    struct buffer_head *bh = bio->bi_private;

    if (unlikely(bio_flagged(bio, BIO_QUIET)))
        set_bit(BH_Quiet, &bh->b_state);

    printk("%s: ...\n", __func__);
    bh->b_end_io(bh, !bio->bi_status);
    printk("%s: ok!\n", __func__);
    bio_put(bio);
}

void submit_bh(blk_opf_t opf, struct buffer_head *bh)
{
    submit_bh_wbc(opf, bh, WRITE_LIFE_NOT_SET, NULL);
}

/**
 * ll_rw_block: low-level access to block devices (DEPRECATED)
 * @op: whether to %READ or %WRITE
 * @op_flags: req_flag_bits
 * @nr: number of &struct buffer_heads in the array
 * @bhs: array of pointers to &struct buffer_head
 *
 * ll_rw_block() takes an array of pointers to &struct buffer_heads, and
 * requests an I/O operation on them, either a %REQ_OP_READ or a %REQ_OP_WRITE.
 * @op_flags contains flags modifying the detailed I/O behavior, most notably
 * %REQ_RAHEAD.
 *
 * This function drops any buffer that it cannot get a lock on (with the
 * BH_Lock state bit), any buffer that appears to be clean when doing a write
 * request, and any buffer that appears to be up-to-date when doing read
 * request.  Further it marks as clean buffers that are processed for
 * writing (the buffer cache won't assume that they are actually clean
 * until the buffer gets unlocked).
 *
 * ll_rw_block sets b_end_io to simple completion handler that marks
 * the buffer up-to-date (if appropriate), unlocks the buffer and wakes
 * any waiters.
 *
 * All of the buffers must be for the same device, and must also be a
 * multiple of the current approved size for the device.
 */
void ll_rw_block(int op, int op_flags,  int nr, struct buffer_head *bhs[])
{
#if 0
    int i;

    for (i = 0; i < nr; i++) {
        struct buffer_head *bh = bhs[i];

        if (!trylock_buffer(bh))
            continue;
        if (op == WRITE) {
            if (test_clear_buffer_dirty(bh)) {
                bh->b_end_io = end_buffer_write_sync;
                get_bh(bh);
                submit_bh(op, op_flags, bh);
                continue;
            }
        } else {
            if (!buffer_uptodate(bh)) {
                bh->b_end_io = end_buffer_read_sync;
                get_bh(bh);
                submit_bh(op, op_flags, bh);
                continue;
            }
        }
        unlock_buffer(bh);
    }
#endif
    booter_panic("No impl.");
}
