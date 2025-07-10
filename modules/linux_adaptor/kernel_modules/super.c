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
    inode_init_once(bd_inode);
    bd_inode->i_data.a_ops = &def_blk_aops;
    bd_inode->i_mapping = &(bd_inode->i_data);
    bd_inode->i_mapping->host = bd_inode;
    bd_inode->i_size = get_capacity(cl_disk) << 9;
    bd_inode->i_mode = S_IFBLK;

    struct block_device *bdev = I_BDEV(bd_inode);
    bdev->bd_disk = cl_disk;
    bdev->bd_inode = bd_inode;

    struct super_block *s;
    s = kmalloc(sizeof(struct super_block), 0);
    s->s_blocksize = 1024;
    s->s_bdev = bdev;
    s->s_bdi = bdi_alloc(0);
    s->s_bdi->dev = kzalloc(sizeof(struct device), GFP_KERNEL);
    set_bit(WB_registered, &s->s_bdi->wb.state);
    bdev->bd_inode->i_sb = s;
    if (fill_super(s, NULL, 0) != 0) {
        booter_panic("ext-fs fill_super error!");
    }

    return s->s_root;
}

/*
 *  trylock_super - try to grab ->s_umount shared
 *  @sb: reference we are trying to grab
 *
 *  Try to prevent fs shutdown.  This is used in places where we
 *  cannot take an active reference but we need to ensure that the
 *  filesystem is not shut down while we are working on it. It returns
 *  false if we cannot acquire s_umount or if we lose the race and
 *  filesystem already got into shutdown, and returns true with the s_umount
 *  lock held in read mode in case of success. On successful return,
 *  the caller must drop the s_umount lock when done.
 *
 *  Note that unlike get_super() et.al. this one does *not* bump ->s_count.
 *  The reason why it's safe is that we are OK with doing trylock instead
 *  of down_read().  There's a couple of places that are OK with that, but
 *  it's very much not a general-purpose interface.
 */
bool trylock_super(struct super_block *sb)
{
    if (down_read_trylock(&sb->s_umount)) {
        if (!hlist_unhashed(&sb->s_instances) &&
            sb->s_root && (sb->s_flags & SB_BORN))
            return true;
        up_read(&sb->s_umount);
    }

    return false;
}
