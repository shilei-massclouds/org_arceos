#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>

#include "booter.h"

//extern int cl_read_block(int blk_nr, void *rbuf, int count);

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

/* Kill _all_ buffers and pagecache , dirty or not.. */
static void kill_bdev(struct block_device *bdev)
{
    struct address_space *mapping = bdev->bd_inode->i_mapping;

    if (mapping->nrpages == 0 && mapping->nrexceptional == 0)
        return;

    invalidate_bh_lrus();
    truncate_inode_pages(mapping, 0);
}

int set_blocksize(struct block_device *bdev, int size)
{
    /* Size must be a power of two, and between 512 and PAGE_SIZE */
    if (size > PAGE_SIZE || size < 512 || !is_power_of_2(size))
        return -EINVAL;

    /* Size cannot be smaller than the size supported by the device */
    if (size < bdev_logical_block_size(bdev))
        return -EINVAL;

    /* Don't change the size if it is same as current */
    if (bdev->bd_inode->i_blkbits != blksize_bits(size)) {
        sync_blockdev(bdev);
        bdev->bd_inode->i_blkbits = blksize_bits(size);
        kill_bdev(bdev);
    }
    return 0;
}

/*
 * Write out and wait upon all the dirty data associated with a block
 * device via its mapping.  Does not take the superblock lock.
 */
int sync_blockdev(struct block_device *bdev)
{
    //return __sync_blockdev(bdev, 1);
    log_error("%s: No impl!\n", __func__);
    return 0;
}

int sb_set_blocksize(struct super_block *sb, int size)
{
    if (set_blocksize(sb->s_bdev, size))
        return 0;
    /* If we get here, we know size is power of two
     * and it's value is between 512 and PAGE_SIZE */
    sb->s_blocksize = size;
    sb->s_blocksize_bits = blksize_bits(size);
    log_error("%s: size(%d) NOTE!\n", __func__, size);
    return sb->s_blocksize;
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

static int submit_bh_wbc(int op, int op_flags, struct buffer_head *bh,
             enum rw_hint write_hint, struct writeback_control *wbc)
{
    struct bio *bio;

    BUG_ON(!buffer_locked(bh));
    BUG_ON(!buffer_mapped(bh));
    BUG_ON(!bh->b_end_io);
    BUG_ON(buffer_delay(bh));
    BUG_ON(buffer_unwritten(bh));

    /*
     * Only clear out a write error when rewriting
     */
    if (test_set_buffer_req(bh) && (op == REQ_OP_WRITE))
        clear_buffer_write_io_error(bh);

    bio = bio_alloc(GFP_NOIO, 1);

    //fscrypt_set_bio_crypt_ctx_bh(bio, bh, GFP_NOIO);

    bio->bi_iter.bi_sector = bh->b_blocknr * (bh->b_size >> 9);
    bio_set_dev(bio, bh->b_bdev);
    bio->bi_write_hint = write_hint;

    bio_add_page(bio, bh->b_page, bh->b_size, bh_offset(bh));
    BUG_ON(bio->bi_iter.bi_size != bh->b_size);

    bio->bi_end_io = end_bio_bh_io_sync;
    bio->bi_private = bh;

    if (buffer_meta(bh))
        op_flags |= REQ_META;
    if (buffer_prio(bh))
        op_flags |= REQ_PRIO;
    bio_set_op_attrs(bio, op, op_flags);

    /* Take care of bh's that straddle the end of the device */
    guard_bio_eod(bio);

    if (wbc) {
        wbc_init_bio(wbc, bio);
        wbc_account_cgroup_owner(wbc, bh->b_page, bh->b_size);
    }

    submit_bio(bio);
    return 0;
}

int submit_bh(int op, int op_flags, struct buffer_head *bh)
{
    return submit_bh_wbc(op, op_flags, bh, 0, NULL);
}

/*
int submit_bh(int op, int op_flags, struct buffer_head *bh)
{
    int blkid;
    int offset;

    printk("%s: impl it. op(%d) b_blocknr(%u) b_size(%u) b_page(%lx)\n",
           __func__, op, bh->b_blocknr, bh->b_size, bh->b_page);

    if (op != READ) {
        booter_panic("Dont support WRITE!\n");
    }

    if (bh->b_size == PAGE_SIZE) {
        blkid = bh->b_blocknr * 8;
        offset = 0;
    } else {
        blkid = bh->b_blocknr * 2;
        offset = 0;
    }

    void *buf = page_to_virt(bh->b_page);
    cl_read_block(blkid, buf, PAGE_SIZE);

    return 0;
}
*/

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
}
