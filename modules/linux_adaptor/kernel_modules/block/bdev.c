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

/* Should we allow writing to mounted block devices? */
static bool bdev_allow_write_mounted = IS_ENABLED(CONFIG_BLK_DEV_WRITE_MOUNTED);

struct bdev_inode {
    struct block_device bdev;
    struct inode vfs_inode;
};

/*
 * pseudo-fs
 */

static  __cacheline_aligned_in_smp DEFINE_MUTEX(bdev_lock);
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

static bool bdev_writes_blocked(struct block_device *bdev)
{
    return bdev->bd_writers < 0;
}

unsigned int block_size(struct block_device *bdev)
{
    return 1 << BD_INODE(bdev)->i_blkbits;
}

/* Kill _all_ buffers and pagecache , dirty or not.. */
static void kill_bdev(struct block_device *bdev)
{
    struct address_space *mapping = bdev->bd_mapping;

    if (mapping_empty(mapping))
        return;

    invalidate_bh_lrus();
    truncate_inode_pages(mapping, 0);
}

int sync_blockdev_nowait(struct block_device *bdev)
{
    if (!bdev)
        return 0;
    return filemap_flush(bdev->bd_mapping);
}

/*
 * Write out and wait upon all the dirty data associated with a block
 * device via its mapping.  Does not take the superblock lock.
 */
int sync_blockdev(struct block_device *bdev)
{
    if (!bdev)
        return 0;
    return filemap_write_and_wait(bdev->bd_mapping);
}

int sb_set_blocksize(struct super_block *sb, int size)
{
    if (set_blocksize(sb->s_bdev_file, size))
        return 0;
    /* If we get here, we know size is power of two
     * and it's value is between 512 and PAGE_SIZE */
    sb->s_blocksize = size;
    sb->s_blocksize_bits = blksize_bits(size);
    return sb->s_blocksize;
}

int sb_min_blocksize(struct super_block *sb, int size)
{
    int minsize = bdev_logical_block_size(sb->s_bdev);
    if (size < minsize)
        size = minsize;
    return sb_set_blocksize(sb, size);
}

int set_blocksize(struct file *file, int size)
{
    struct inode *inode = file->f_mapping->host;
    struct block_device *bdev = I_BDEV(inode);

    /* Size must be a power of two, and between 512 and PAGE_SIZE */
    if (size > PAGE_SIZE || size < 512 || !is_power_of_2(size))
        return -EINVAL;

    /* Size cannot be smaller than the size supported by the device */
    if (size < bdev_logical_block_size(bdev))
        return -EINVAL;

    if (!file->private_data)
        return -EINVAL;

    /* Don't change the size if it is same as current */
    if (inode->i_blkbits != blksize_bits(size)) {
        /*
         * Flush and truncate the pagecache before we reconfigure the
         * mapping geometry because folio sizes are variable now.  If a
         * reader has already allocated a folio whose size is smaller
         * than the new min_order but invokes readahead after the new
         * min_order becomes visible, readahead will think there are
         * "zero" blocks per folio and crash.  Take the inode and
         * invalidation locks to avoid racing with
         * read/write/fallocate.
         */
        inode_lock(inode);
        filemap_invalidate_lock(inode->i_mapping);

        sync_blockdev(bdev);
        kill_bdev(bdev);

        inode->i_blkbits = blksize_bits(size);
        kill_bdev(bdev);
        filemap_invalidate_unlock(inode->i_mapping);
        inode_unlock(inode);
    }
    return 0;
}

bool disk_live(struct gendisk *disk)
{
    return !inode_unhashed(BD_INODE(disk->part0));
}

static void bdev_write_inode(struct block_device *bdev)
{
    PANIC("");
}

static void blkdev_flush_mapping(struct block_device *bdev)
{
    WARN_ON_ONCE(bdev->bd_holders);
    sync_blockdev(bdev);
    kill_bdev(bdev);
    bdev_write_inode(bdev);
}

static void blkdev_put_whole(struct block_device *bdev)
{
    if (atomic_dec_and_test(&bdev->bd_openers))
        blkdev_flush_mapping(bdev);
    if (bdev->bd_disk->fops->release)
        bdev->bd_disk->fops->release(bdev->bd_disk);
}

static void set_init_blocksize(struct block_device *bdev)
{
    unsigned int bsize = bdev_logical_block_size(bdev);
    loff_t size = i_size_read(BD_INODE(bdev));

    while (bsize < PAGE_SIZE) {
        if (size & bsize)
            break;
        bsize <<= 1;
    }
    BD_INODE(bdev)->i_blkbits = blksize_bits(bsize);
}

static int blkdev_get_whole(struct block_device *bdev, blk_mode_t mode)
{
    struct gendisk *disk = bdev->bd_disk;
    int ret;

    if (disk->fops->open) {
        ret = disk->fops->open(disk, mode);
        if (ret) {
            /* avoid ghost partitions on a removed medium */
            if (ret == -ENOMEDIUM &&
                 test_bit(GD_NEED_PART_SCAN, &disk->state))
                bdev_disk_changed(disk, true);
            return ret;
        }
    }

    if (!atomic_read(&bdev->bd_openers))
        set_init_blocksize(bdev);
    atomic_inc(&bdev->bd_openers);
    if (test_bit(GD_NEED_PART_SCAN, &disk->state)) {
        pr_err("%s: GD_NEED_PART_SCAN\n", __func__);
#if 0
        /*
         * Only return scanning errors if we are called from contexts
         * that explicitly want them, e.g. the BLKRRPART ioctl.
         */
        ret = bdev_disk_changed(disk, false);
        if (ret && (mode & BLK_OPEN_STRICT_SCAN)) {
            blkdev_put_whole(bdev);
            return ret;
        }
#endif
    }
    return 0;
}

static int blkdev_get_part(struct block_device *part, blk_mode_t mode)
{
    PANIC("");
}

static bool bdev_may_open(struct block_device *bdev, blk_mode_t mode)
{
    if (bdev_allow_write_mounted)
        return true;
    /* Writes blocked? */
    if (mode & BLK_OPEN_WRITE && bdev_writes_blocked(bdev))
        return false;
    if (mode & BLK_OPEN_RESTRICT_WRITES && bdev->bd_writers > 0)
        return false;
    return true;
}

/**
 * bd_may_claim - test whether a block device can be claimed
 * @bdev: block device of interest
 * @holder: holder trying to claim @bdev
 * @hops: holder ops
 *
 * Test whether @bdev can be claimed by @holder.
 *
 * RETURNS:
 * %true if @bdev can be claimed, %false otherwise.
 */
static bool bd_may_claim(struct block_device *bdev, void *holder,
        const struct blk_holder_ops *hops)
{
    struct block_device *whole = bdev_whole(bdev);

    lockdep_assert_held(&bdev_lock);

    if (bdev->bd_holder) {
        /*
         * The same holder can always re-claim.
         */
        if (bdev->bd_holder == holder) {
            if (WARN_ON_ONCE(bdev->bd_holder_ops != hops))
                return false;
            return true;
        }
        return false;
    }

    /*
     * If the whole devices holder is set to bd_may_claim, a partition on
     * the device is claimed, but not the whole device.
     */
    if (whole != bdev &&
        whole->bd_holder && whole->bd_holder != bd_may_claim)
        return false;
    return true;
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

struct block_device *blkdev_get_no_open(dev_t dev)
{
    struct block_device *bdev;
    struct inode *inode;

    inode = ilookup(blockdev_superblock, dev);
    if (!inode && IS_ENABLED(CONFIG_BLOCK_LEGACY_AUTOLOAD)) {
        blk_request_module(dev);
        inode = ilookup(blockdev_superblock, dev);
        if (inode)
            pr_warn_ratelimited(
"block device autoloading is deprecated and will be removed.\n");
    }
    if (!inode)
        return NULL;

    /* switch from the inode reference to a device mode one: */
    bdev = &BDEV_I(inode)->bdev;
    if (!kobject_get_unless_zero(&bdev->bd_device.kobj))
        bdev = NULL;
    iput(inode);
    return bdev;
}

/**
 * lookup_bdev() - Look up a struct block_device by name.
 * @pathname: Name of the block device in the filesystem.
 * @dev: Pointer to the block device's dev_t, if found.
 *
 * Lookup the block device's dev_t at @pathname in the current
 * namespace if possible and return it in @dev.
 *
 * Context: May sleep.
 * Return: 0 if succeeded, negative errno otherwise.
 */
int lookup_bdev(const char *pathname, dev_t *dev)
{
    pr_err("%s: No impl.", __func__);
    if (strcmp(pathname, "/dev/root") == 0) {
        *dev = MKDEV(0xFE, 0x00);
        return 0;
    }
    PANIC("Bad blkdev name.");
}

static void bdev_block_writes(struct block_device *bdev)
{
    bdev->bd_writers--;
}

static void bd_clear_claiming(struct block_device *whole, void *holder)
{
    lockdep_assert_held(&bdev_lock);
    /* tell others that we're done */
    BUG_ON(whole->bd_claiming != holder);
    whole->bd_claiming = NULL;
    wake_up_var(&whole->bd_claiming);
}

/**
 * bd_finish_claiming - finish claiming of a block device
 * @bdev: block device of interest
 * @holder: holder that has claimed @bdev
 * @hops: block device holder operations
 *
 * Finish exclusive open of a block device. Mark the device as exlusively
 * open by the holder and wake up all waiters for exclusive open to finish.
 */
static void bd_finish_claiming(struct block_device *bdev, void *holder,
        const struct blk_holder_ops *hops)
{
    struct block_device *whole = bdev_whole(bdev);

    mutex_lock(&bdev_lock);
    BUG_ON(!bd_may_claim(bdev, holder, hops));
    /*
     * Note that for a whole device bd_holders will be incremented twice,
     * and bd_holder will be set to bd_may_claim before being set to holder
     */
    whole->bd_holders++;
    whole->bd_holder = bd_may_claim;
    bdev->bd_holders++;
    mutex_lock(&bdev->bd_holder_lock);
    bdev->bd_holder = holder;
    bdev->bd_holder_ops = hops;
    mutex_unlock(&bdev->bd_holder_lock);
    bd_clear_claiming(whole, holder);
    mutex_unlock(&bdev_lock);
}

static void bdev_claim_write_access(struct block_device *bdev, blk_mode_t mode)
{
    if (bdev_allow_write_mounted)
        return;

    /* Claim exclusive or shared write access. */
    if (mode & BLK_OPEN_RESTRICT_WRITES)
        bdev_block_writes(bdev);
    else if (mode & BLK_OPEN_WRITE)
        bdev->bd_writers++;
}

/*
 * If BLK_OPEN_WRITE_IOCTL is set then this is a historical quirk
 * associated with the floppy driver where it has allowed ioctls if the
 * file was opened for writing, but does not allow reads or writes.
 * Make sure that this quirk is reflected in @f_flags.
 *
 * It can also happen if a block device is opened as O_RDWR | O_WRONLY.
 */
static unsigned blk_to_file_flags(blk_mode_t mode)
{
    unsigned int flags = 0;

    if ((mode & (BLK_OPEN_READ | BLK_OPEN_WRITE)) ==
        (BLK_OPEN_READ | BLK_OPEN_WRITE))
        flags |= O_RDWR;
    else if (mode & BLK_OPEN_WRITE_IOCTL)
        flags |= O_RDWR | O_WRONLY;
    else if (mode & BLK_OPEN_WRITE)
        flags |= O_WRONLY;
    else if (mode & BLK_OPEN_READ)
        flags |= O_RDONLY; /* homeopathic, because O_RDONLY is 0 */
    else
        WARN_ON_ONCE(true);

    if (mode & BLK_OPEN_NDELAY)
        flags |= O_NDELAY;

    return flags;
}

struct file *bdev_file_open_by_dev(dev_t dev, blk_mode_t mode, void *holder,
                   const struct blk_holder_ops *hops)
{
    struct file *bdev_file;
    struct block_device *bdev;
    unsigned int flags;
    int ret;

    ret = bdev_permission(dev, mode, holder);
    if (ret)
        return ERR_PTR(ret);

    bdev = blkdev_get_no_open(dev);
    if (!bdev)
        return ERR_PTR(-ENXIO);

    flags = blk_to_file_flags(mode);
    bdev_file = alloc_file_pseudo_noaccount(BD_INODE(bdev),
            blockdev_mnt, "", flags | O_LARGEFILE, &def_blk_fops);
    if (IS_ERR(bdev_file)) {
        blkdev_put_no_open(bdev);
        return bdev_file;
    }
    ihold(BD_INODE(bdev));

    ret = bdev_open(bdev, mode, holder, hops, bdev_file);
    if (ret) {
        /* We failed to open the block device. Let ->release() know. */
        bdev_file->private_data = ERR_PTR(ret);
        fput(bdev_file);
        return ERR_PTR(ret);
    }
    return bdev_file;
}

/**
 * bdev_open - open a block device
 * @bdev: block device to open
 * @mode: open mode (BLK_OPEN_*)
 * @holder: exclusive holder identifier
 * @hops: holder operations
 * @bdev_file: file for the block device
 *
 * Open the block device. If @holder is not %NULL, the block device is opened
 * with exclusive access.  Exclusive opens may nest for the same @holder.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * zero on success, -errno on failure.
 */
int bdev_open(struct block_device *bdev, blk_mode_t mode, void *holder,
          const struct blk_holder_ops *hops, struct file *bdev_file)
{
    bool unblock_events = true;
    struct gendisk *disk = bdev->bd_disk;
    int ret;

    if (holder) {
        mode |= BLK_OPEN_EXCL;
        ret = bd_prepare_to_claim(bdev, holder, hops);
        if (ret)
            return ret;
    } else {
        if (WARN_ON_ONCE(mode & BLK_OPEN_EXCL))
            return -EIO;
    }

    //disk_block_events(disk);

    mutex_lock(&disk->open_mutex);
    ret = -ENXIO;
    if (!disk_live(disk))
        goto abort_claiming;
    if (!try_module_get(disk->fops->owner))
        goto abort_claiming;
    ret = -EBUSY;
    if (!bdev_may_open(bdev, mode))
        goto put_module;
    if (bdev_is_partition(bdev))
        ret = blkdev_get_part(bdev, mode);
    else
        ret = blkdev_get_whole(bdev, mode);
    if (ret)
        goto put_module;
    bdev_claim_write_access(bdev, mode);
    if (holder) {
        bd_finish_claiming(bdev, holder, hops);

        /*
         * Block event polling for write claims if requested.  Any write
         * holder makes the write_holder state stick until all are
         * released.  This is good enough and tracking individual
         * writeable reference is too fragile given the way @mode is
         * used in blkdev_get/put().
         */
        if ((mode & BLK_OPEN_WRITE) &&
            !bdev_test_flag(bdev, BD_WRITE_HOLDER) &&
            (disk->event_flags & DISK_EVENT_FLAG_BLOCK_ON_EXCL_WRITE)) {
            bdev_set_flag(bdev, BD_WRITE_HOLDER);
            unblock_events = false;
        }
    }
    mutex_unlock(&disk->open_mutex);

#if 0
    if (unblock_events)
        disk_unblock_events(disk);
#endif

    bdev_file->f_flags |= O_LARGEFILE;
    bdev_file->f_mode |= FMODE_CAN_ODIRECT;
    if (bdev_nowait(bdev))
        bdev_file->f_mode |= FMODE_NOWAIT;
    if (mode & BLK_OPEN_RESTRICT_WRITES)
        bdev_file->f_mode |= FMODE_WRITE_RESTRICTED;
    bdev_file->f_mapping = bdev->bd_mapping;
    bdev_file->f_wb_err = filemap_sample_wb_err(bdev_file->f_mapping);
    bdev_file->private_data = holder;

    return 0;
put_module:
    module_put(disk->fops->owner);
abort_claiming:
    if (holder)
        bd_abort_claiming(bdev, holder);
    mutex_unlock(&disk->open_mutex);
    //disk_unblock_events(disk);
    return ret;
}

/**
 * bd_abort_claiming - abort claiming of a block device
 * @bdev: block device of interest
 * @holder: holder that has claimed @bdev
 *
 * Abort claiming of a block device when the exclusive open failed. This can be
 * also used when exclusive open is not actually desired and we just needed
 * to block other exclusive openers for a while.
 */
void bd_abort_claiming(struct block_device *bdev, void *holder)
{
    mutex_lock(&bdev_lock);
    bd_clear_claiming(bdev_whole(bdev), holder);
    mutex_unlock(&bdev_lock);
}

/**
 * bd_prepare_to_claim - claim a block device
 * @bdev: block device of interest
 * @holder: holder trying to claim @bdev
 * @hops: holder ops.
 *
 * Claim @bdev.  This function fails if @bdev is already claimed by another
 * holder and waits if another claiming is in progress. return, the caller
 * has ownership of bd_claiming and bd_holder[s].
 *
 * RETURNS:
 * 0 if @bdev can be claimed, -EBUSY otherwise.
 */
int bd_prepare_to_claim(struct block_device *bdev, void *holder,
        const struct blk_holder_ops *hops)
{
    struct block_device *whole = bdev_whole(bdev);

    if (WARN_ON_ONCE(!holder))
        return -EINVAL;
retry:
    mutex_lock(&bdev_lock);
    /* if someone else claimed, fail */
    if (!bd_may_claim(bdev, holder, hops)) {
        mutex_unlock(&bdev_lock);
        return -EBUSY;
    }

    /* if claiming is already in progress, wait for it to finish */
    if (whole->bd_claiming) {
        wait_queue_head_t *wq = __var_waitqueue(&whole->bd_claiming);
        DEFINE_WAIT(wait);

        prepare_to_wait(wq, &wait, TASK_UNINTERRUPTIBLE);
        mutex_unlock(&bdev_lock);
        schedule();
        finish_wait(wq, &wait);
        goto retry;
    }

    /* yay, all mine */
    whole->bd_claiming = holder;
    mutex_unlock(&bdev_lock);
    return 0;
}

struct block_device *file_bdev(struct file *bdev_file)
{
    return I_BDEV(bdev_file->f_mapping->host);
}

int bdev_permission(dev_t dev, blk_mode_t mode, void *holder)
{
    int ret;

#if 0
    ret = devcgroup_check_permission(DEVCG_DEV_BLOCK,
            MAJOR(dev), MINOR(dev),
            ((mode & BLK_OPEN_READ) ? DEVCG_ACC_READ : 0) |
            ((mode & BLK_OPEN_WRITE) ? DEVCG_ACC_WRITE : 0));
    if (ret)
        return ret;
#endif

    /* Blocking writes requires exclusive opener */
    if (mode & BLK_OPEN_RESTRICT_WRITES && !holder)
        return -EINVAL;

    /*
     * We're using error pointers to indicate to ->release() when we
     * failed to open that block device. Also this doesn't make sense.
     */
    if (WARN_ON_ONCE(IS_ERR(holder)))
        return -EINVAL;

    return 0;
}

/* Invalidate clean unused buffers and pagecache. */
void invalidate_bdev(struct block_device *bdev)
{
    struct address_space *mapping = bdev->bd_mapping;

    if (mapping->nrpages) {
        invalidate_bh_lrus();
        lru_add_drain_all();    /* make sure all lru add caches are flushed */
        invalidate_mapping_pages(mapping, 0, -1);
    }
}

static inline bool bdev_unclaimed(const struct file *bdev_file)
{
    return bdev_file->private_data == BDEV_I(bdev_file->f_mapping->host);
}

static void bdev_unblock_writes(struct block_device *bdev)
{
    bdev->bd_writers++;
}

static void bdev_yield_write_access(struct file *bdev_file)
{
    struct block_device *bdev;

    if (bdev_allow_write_mounted)
        return;

    if (bdev_unclaimed(bdev_file))
        return;

    bdev = file_bdev(bdev_file);

    if (bdev_file->f_mode & FMODE_WRITE_RESTRICTED)
        bdev_unblock_writes(bdev);
    else if (bdev_file->f_mode & FMODE_WRITE)
        bdev->bd_writers--;

    PANIC("");
}

static void bd_end_claim(struct block_device *bdev, void *holder)
{
    struct block_device *whole = bdev_whole(bdev);
    bool unblock = false;

    /*
     * Release a claim on the device.  The holder fields are protected with
     * bdev_lock.  open_mutex is used to synchronize disk_holder unlinking.
     */
    mutex_lock(&bdev_lock);
    WARN_ON_ONCE(bdev->bd_holder != holder);
    WARN_ON_ONCE(--bdev->bd_holders < 0);
    WARN_ON_ONCE(--whole->bd_holders < 0);
    if (!bdev->bd_holders) {
        mutex_lock(&bdev->bd_holder_lock);
        bdev->bd_holder = NULL;
        bdev->bd_holder_ops = NULL;
        mutex_unlock(&bdev->bd_holder_lock);
        if (bdev_test_flag(bdev, BD_WRITE_HOLDER))
            unblock = true;
    }
    if (!whole->bd_holders)
        whole->bd_holder = NULL;
    mutex_unlock(&bdev_lock);

    /*
     * If this was the last claim, remove holder link and unblock evpoll if
     * it was a write holder.
     */
    if (unblock) {
        //disk_unblock_events(bdev->bd_disk);
        bdev_clear_flag(bdev, BD_WRITE_HOLDER);
    }
}

static inline void bd_yield_claim(struct file *bdev_file)
{
    struct block_device *bdev = file_bdev(bdev_file);
    void *holder = bdev_file->private_data;

    lockdep_assert_held(&bdev->bd_disk->open_mutex);

    if (WARN_ON_ONCE(IS_ERR_OR_NULL(holder)))
        return;

    if (!bdev_unclaimed(bdev_file))
        bd_end_claim(bdev, holder);
}

/**
 * bdev_fput - yield claim to the block device and put the file
 * @bdev_file: open block device
 *
 * Yield claim on the block device and put the file. Ensure that the
 * block device can be reclaimed before the file is closed which is a
 * deferred operation.
 */
void bdev_fput(struct file *bdev_file)
{
    if (WARN_ON_ONCE(bdev_file->f_op != &def_blk_fops))
        return;

    if (bdev_file->private_data) {
        struct block_device *bdev = file_bdev(bdev_file);
        struct gendisk *disk = bdev->bd_disk;

        mutex_lock(&disk->open_mutex);
        bdev_yield_write_access(bdev_file);
        bd_yield_claim(bdev_file);
        /*
         * Tell release we already gave up our hold on the
         * device and if write restrictions are available that
         * we already gave up write access to the device.
         */
        bdev_file->private_data = BDEV_I(bdev_file->f_mapping->host);
        mutex_unlock(&disk->open_mutex);
    }

    fput(bdev_file);
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
