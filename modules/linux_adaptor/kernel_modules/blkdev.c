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
    log_error("%s: impl it. op(%d) b_blocknr(%u) b_size(%u) b_page(%lx)\n",
              __func__, op, bh->b_blocknr, bh->b_size, bh->b_page);
}
