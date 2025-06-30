#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>

#include "booter.h"

extern int cl_read_block(int blk_nr, void *rbuf, int count);

int sb_min_blocksize(struct super_block *sb, int size)
{
    return BLOCK_SIZE;
}

struct buffer_head *
__bread_gfp(struct block_device *bdev, sector_t block,
           unsigned size, gfp_t gfp)
{
    printk("%s: blknr(%llu) size(%u) BLOCK_SIZE(%u)\n",
           __func__, block, size, BLOCK_SIZE);

    int blkid;
    int offset;
    if (size == 4096) {
        blkid = block * 8;
        offset = 0;
    } else {
        blkid = block * 2;
        offset = 0;
    }

    void *buf = alloc_pages_exact(4096, 0);
    cl_read_block(blkid, buf, 4096);

    struct buffer_head *bh = kmalloc(sizeof(struct buffer_head), 0);
    bh->b_data = buf + offset;
    bh->b_size = 4096;
    bh->b_blocknr = block;
    bh->b_page = virt_to_page(buf);
    set_buffer_uptodate(bh);
    return bh;
}

void __brelse(struct buffer_head * buf)
{
    log_debug("%s: impl it.\n", __func__);
}

int sb_set_blocksize(struct super_block *sb, int size)
{
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

int submit_bh(int op, int op_flags, struct buffer_head *bh)
{
    int blkid;
    int offset;

    log_debug("%s: impl it. op(%d) b_blocknr(%u) b_size(%u) b_page(%lx)\n",
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
