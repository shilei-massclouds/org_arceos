#include <linux/blk_types.h>
#include <linux/blkdev.h>

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
