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
#include <linux/mpage.h>
#include "../fs/internal.h"
#include "blk.h"

#include "../adaptor.h"

struct bdev_inode {
    struct block_device bdev;
    struct inode vfs_inode;
};

static struct kmem_cache *bdev_cachep __ro_after_init;

struct super_block *blockdev_superblock __ro_after_init;
static struct vfsmount *blockdev_mnt __ro_after_init;

static inline struct bdev_inode *BDEV_I(struct inode *inode)
{
    return container_of(inode, struct bdev_inode, vfs_inode);
}

static inline struct inode *BD_INODE(struct block_device *bdev)
{
    return &container_of(bdev, struct bdev_inode, bdev)->vfs_inode;
}

struct block_device *I_BDEV(struct inode *inode)
{
    return &BDEV_I(inode)->bdev;
}

bool disk_live(struct gendisk *disk)
{
    return !inode_unhashed(BD_INODE(disk->part0));
}

struct block_device *bdev_alloc(struct gendisk *disk, u8 partno)
{
    struct block_device *bdev;
    struct inode *inode;

    inode = new_inode(blockdev_superblock);
    if (!inode)
        return NULL;
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
    return bdev;
}

static void init_once(void *data)
{
    struct bdev_inode *ei = data;

    inode_init_once(&ei->vfs_inode);
}

static struct inode *bdev_alloc_inode(struct super_block *sb)
{
    struct bdev_inode *ei = alloc_inode_sb(sb, bdev_cachep, GFP_KERNEL);

    if (!ei)
        return NULL;
    memset(&ei->bdev, 0, sizeof(ei->bdev));

#if 0
    if (security_bdev_alloc(&ei->bdev)) {
        kmem_cache_free(bdev_cachep, ei);
        return NULL;
    }
#endif
    return &ei->vfs_inode;
}

static void bdev_free_inode(struct inode *inode)
{
    PANIC("");
}

static void bdev_evict_inode(struct inode *inode)
{
    PANIC("");
}

static int blkdev_get_block(struct inode *inode, sector_t iblock,
		struct buffer_head *bh, int create)
{
	bh->b_bdev = I_BDEV(inode);
	bh->b_blocknr = iblock;
	set_buffer_mapped(bh);
	return 0;
}

/*
 * We cannot call mpage_writepages() as it does not take the buffer lock.
 * We must use block_write_full_folio() directly which holds the buffer
 * lock.  The buffer lock provides the synchronisation with writeback
 * that filesystems rely on when they use the blockdev's mapping.
 */
static int blkdev_writepages(struct address_space *mapping,
		struct writeback_control *wbc)
{
	struct blk_plug plug;
	int err;

	blk_start_plug(&plug);
	err = write_cache_pages(mapping, wbc, block_write_full_folio,
			blkdev_get_block);
	blk_finish_plug(&plug);

	return err;
}

static int blkdev_read_folio(struct file *file, struct folio *folio)
{
	return block_read_full_folio(folio, blkdev_get_block);
}

static void blkdev_readahead(struct readahead_control *rac)
{
	mpage_readahead(rac, blkdev_get_block);
}

static int blkdev_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, struct folio **foliop, void **fsdata)
{
	return block_write_begin(mapping, pos, len, foliop, blkdev_get_block);
}

static int blkdev_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned copied, struct folio *folio,
		void *fsdata)
{
	int ret;
	ret = block_write_end(file, mapping, pos, len, copied, folio, fsdata);

	folio_unlock(folio);
	folio_put(folio);

	return ret;
}

const struct address_space_operations def_blk_aops = {
	.dirty_folio	= block_dirty_folio,
	.invalidate_folio = block_invalidate_folio,
	.read_folio	= blkdev_read_folio,
	.readahead	= blkdev_readahead,
	.writepages	= blkdev_writepages,
	.write_begin	= blkdev_write_begin,
	.write_end	= blkdev_write_end,
	.migrate_folio	= buffer_migrate_folio_norefs,
	.is_dirty_writeback = buffer_check_dirty_writeback,
};

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

void bdev_drop(struct block_device *bdev)
{
    iput(BD_INODE(bdev));
}

void bdev_set_nr_sectors(struct block_device *bdev, sector_t sectors)
{
    spin_lock(&bdev->bd_size_lock);
    i_size_write(BD_INODE(bdev), (loff_t)sectors << SECTOR_SHIFT);
    bdev->bd_nr_sectors = sectors;
    spin_unlock(&bdev->bd_size_lock);
}

void bdev_add(struct block_device *bdev, dev_t dev)
{
    struct inode *inode = BD_INODE(bdev);
    if (bdev_stable_writes(bdev))
        mapping_set_stable_writes(bdev->bd_mapping);
    bdev->bd_dev = dev;
    inode->i_rdev = dev;
    inode->i_ino = dev;
    insert_inode_hash(inode);
}

void __init bdev_cache_init(void)
{
    int err;

    bdev_cachep = kmem_cache_create("bdev_cache", sizeof(struct bdev_inode),
            0, (SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT|
                SLAB_ACCOUNT|SLAB_PANIC),
            init_once);
    err = register_filesystem(&bd_type);
    if (err)
        panic("Cannot register bdev pseudo-fs");
    blockdev_mnt = kern_mount(&bd_type);
    if (IS_ERR(blockdev_mnt))
        panic("Cannot create bdev pseudo-fs");
    blockdev_superblock = blockdev_mnt->mnt_sb;   /* For writeback */
}
