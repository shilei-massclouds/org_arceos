#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>

struct bdev_inode {
    struct block_device bdev;
    struct inode vfs_inode;
};

static inline struct bdev_inode *BDEV_I(struct inode *inode)
{
    return container_of(inode, struct bdev_inode, vfs_inode);
}

struct block_device *I_BDEV(struct inode *inode)
{
    return &BDEV_I(inode)->bdev;
}

struct inode *cl_bdev_alloc_inode(void)
{
    struct bdev_inode *ei = kmalloc(sizeof(struct bdev_inode), 0);
    if (!ei)
        return NULL;
    return &ei->vfs_inode;
}

static int
blkdev_get_block(struct inode *inode, sector_t iblock,
        struct buffer_head *bh, int create)
{
    bh->b_bdev = I_BDEV(inode);
    bh->b_blocknr = iblock;
    set_buffer_mapped(bh);
    return 0;
}

static int blkdev_writepage(struct page *page, struct writeback_control *wbc)
{
    return block_write_full_page(page, blkdev_get_block, wbc);
}

static int blkdev_writepages(struct address_space *mapping,
                 struct writeback_control *wbc)
{
    return generic_writepages(mapping, wbc);
}

// Note: impl def_blk_aops.
const struct address_space_operations def_blk_aops = {
    .writepage  = blkdev_writepage,
    .writepages = blkdev_writepages,
};
