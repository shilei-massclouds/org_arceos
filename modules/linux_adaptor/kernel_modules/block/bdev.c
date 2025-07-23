#include <linux/init.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/major.h>
#include <linux/device_cgroup.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/backing-dev.h>
#include <linux/module.h>
#include <linux/blkpg.h>
#include <linux/magic.h>
#include <linux/buffer_head.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/part_stat.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include "../fs/internal.h"
#include "blk.h"

#include "../adaptor.h"

struct bdev_inode {
    struct block_device bdev;
    struct inode vfs_inode;
};

static struct kmem_cache *bdev_cachep __ro_after_init;

struct super_block *blockdev_superblock __ro_after_init;

bool disk_live(struct gendisk *disk)
{
    PANIC("");
    //return !inode_unhashed(BD_INODE(disk->part0));
}

struct block_device *bdev_alloc(struct gendisk *disk, u8 partno)
{
    struct block_device *bdev;
    struct inode *inode;

    inode = new_inode(blockdev_superblock);
    if (!inode)
        return NULL;
#if 0
    inode->i_mode = S_IFBLK;
    inode->i_rdev = 0;
    inode->i_data.a_ops = &def_blk_aops;
    mapping_set_gfp_mask(&inode->i_data, GFP_USER);

    bdev = I_BDEV(inode);
    mutex_init(&bdev->bd_fsfreeze_mutex);
    spin_lock_init(&bdev->bd_size_lock);
    mutex_init(&bdev->bd_holder_lock);
    atomic_set(&bdev->__bd_flags, partno);
    bdev->bd_mapping = &inode->i_data;
    bdev->bd_queue = disk->queue;
    if (partno && bdev_test_flag(disk->part0, BD_HAS_SUBMIT_BIO))
        bdev_set_flag(bdev, BD_HAS_SUBMIT_BIO);
    bdev->bd_stats = alloc_percpu(struct disk_stats);
    if (!bdev->bd_stats) {
        iput(inode);
        return NULL;
    }
    bdev->bd_disk = disk;
#endif
    PANIC("");
    return bdev;
}

static void init_once(void *data)
{
    struct bdev_inode *ei = data;

    inode_init_once(&ei->vfs_inode);
}

static struct inode *bdev_alloc_inode(struct super_block *sb)
{
    PANIC("");
}

static void bdev_free_inode(struct inode *inode)
{
    PANIC("");
}

static void bdev_evict_inode(struct inode *inode)
{
    PANIC("");
}

static const struct super_operations bdev_sops = {
    .statfs = simple_statfs,
    .alloc_inode = bdev_alloc_inode,
    .free_inode = bdev_free_inode,
    .drop_inode = generic_delete_inode,
    .evict_inode = bdev_evict_inode,
};

static int bd_init_fs_context(struct fs_context *fc)
{
    struct pseudo_fs_context *ctx = init_pseudo(fc, BDEVFS_MAGIC);
    if (!ctx)
        return -ENOMEM;
    fc->s_iflags |= SB_I_CGROUPWB;
    ctx->ops = &bdev_sops;
    return 0;
}

static struct file_system_type bd_type = {
    .name       = "bdev",
    .init_fs_context = bd_init_fs_context,
    .kill_sb    = kill_anon_super,
};

void __init bdev_cache_init(void)
{
    int err;

    bdev_cachep = kmem_cache_create("bdev_cache", sizeof(struct bdev_inode),
            0, (SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT|
                SLAB_ACCOUNT|SLAB_PANIC),
            init_once);
    err = register_filesystem(&bd_type);
#if 0
    if (err)
        panic("Cannot register bdev pseudo-fs");
    blockdev_mnt = kern_mount(&bd_type);
    if (IS_ERR(blockdev_mnt))
        panic("Cannot create bdev pseudo-fs");
    blockdev_superblock = blockdev_mnt->mnt_sb;   /* For writeback */
#endif
    PANIC("");
}
