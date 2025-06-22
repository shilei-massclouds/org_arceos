#include <linux/fs.h>
#include <linux/buffer_head.h>

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
    return bh;
}

void __brelse(struct buffer_head * buf)
{
    log_error("%s: impl it.\n", __func__);
}
