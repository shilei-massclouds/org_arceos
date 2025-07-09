#include <linux/fs.h>
#include <linux/blk_types.h>
#include <linux/backing-dev.h>

#include "booter.h"

extern void *kmalloc(size_t size, gfp_t flags);
extern struct inode *cl_bdev_alloc_inode(void);
extern struct gendisk *cl_disk;

// Note: impl def_blk_aops.
static const struct address_space_operations def_blk_aops;

struct dentry *mount_bdev(struct file_system_type *fs_type,
    int flags, const char *dev_name, void *data,
    int (*fill_super)(struct super_block *, void *, int))
{
    if (fill_super == NULL) {
        booter_panic("No ext2 fill_super!");
    }
    if (cl_disk == NULL) {
        booter_panic("No gendisk!");
    }

    struct inode *bd_inode = cl_bdev_alloc_inode();
    bd_inode->i_data.a_ops = &def_blk_aops;
    bd_inode->i_mapping = &(bd_inode->i_data);
    bd_inode->i_mapping->host = bd_inode;
    bd_inode->i_size = get_capacity(cl_disk) << 9;

    struct block_device *bdev = I_BDEV(bd_inode);
    bdev->bd_disk = cl_disk;
    bdev->bd_inode = bd_inode;

    struct super_block *s;
    s = kmalloc(sizeof(struct super_block), 0);
    s->s_blocksize = 1024;
    s->s_bdev = bdev;
    s->s_bdi = kmalloc(sizeof(struct backing_dev_info), 0);
    bdev->bd_inode->i_sb = s;
    if (fill_super(s, NULL, 0) != 0) {
        booter_panic("ext-fs fill_super error!");
    }

    return s->s_root;
}
