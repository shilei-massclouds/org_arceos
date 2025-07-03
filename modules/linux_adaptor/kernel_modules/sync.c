#include <linux/fs.h>

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
