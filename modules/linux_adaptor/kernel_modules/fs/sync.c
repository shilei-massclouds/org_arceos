#include <linux/blkdev.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/writeback.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/backing-dev.h>
#include "internal.h"
#include "../adaptor.h"

/*
 * Write out and wait upon all dirty data associated with this
 * superblock.  Filesystem data as well as the underlying block
 * device.  Takes the superblock lock.
 */
int sync_filesystem(struct super_block *sb)
{
    int ret = 0;

    /*
     * We need to be protected against the filesystem going from
     * r/o to r/w or vice versa.
     */
    WARN_ON(!rwsem_is_locked(&sb->s_umount));

    /*
     * No point in syncing out anything if the filesystem is read-only.
     */
    if (sb_rdonly(sb))
        return 0;

    /*
     * Do the filesystem syncing work.  For simple filesystems
     * writeback_inodes_sb(sb) just dirties buffers with inodes so we have
     * to submit I/O for these buffers via sync_blockdev().  This also
     * speeds up the wait == 1 case since in that case write_inode()
     * methods call sync_dirty_buffer() and thus effectively write one block
     * at a time.
     */
    printk("%s: step1\n", __func__);
    writeback_inodes_sb(sb, WB_REASON_SYNC);
    printk("%s: step2\n", __func__);
    if (sb->s_op->sync_fs) {
    printk("%s: step3\n", __func__);
        ret = sb->s_op->sync_fs(sb, 0);
        if (ret)
            return ret;
    }
    ret = sync_blockdev_nowait(sb->s_bdev);
    if (ret)
        return ret;

    sync_inodes_sb(sb);
    if (sb->s_op->sync_fs) {
        ret = sb->s_op->sync_fs(sb, 1);
        if (ret)
            return ret;
    }
    PANIC("");
    return sync_blockdev(sb->s_bdev);
}

/**
 * vfs_fsync_range - helper to sync a range of data & metadata to disk
 * @file:       file to sync
 * @start:      offset in bytes of the beginning of data range to sync
 * @end:        offset in bytes of the end of data range (inclusive)
 * @datasync:       perform only datasync
 *
 * Write back data in range @start..@end and metadata for @file to disk.  If
 * @datasync is set only metadata needed to access modified file data is
 * written.
 */
int vfs_fsync_range(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct inode *inode = file->f_mapping->host;

    if (!file->f_op->fsync)
        return -EINVAL;
    if (!datasync && (inode->i_state & I_DIRTY_TIME))
        mark_inode_dirty_sync(inode);
    return file->f_op->fsync(file, start, end, datasync);
}
