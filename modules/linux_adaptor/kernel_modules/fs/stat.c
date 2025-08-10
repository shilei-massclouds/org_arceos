#include <linux/blkdev.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/compat.h>
#include <linux/iversion.h>

#include <linux/uaccess.h>
#include <asm/unistd.h>

#include "internal.h"
#include "mount.h"
#include "../adaptor.h"

/* Caller is here responsible for sufficient locking (ie. inode->i_lock) */
void __inode_add_bytes(struct inode *inode, loff_t bytes)
{
    inode->i_blocks += bytes >> 9;
    bytes &= 511;
    inode->i_bytes += bytes;
    if (inode->i_bytes >= 512) {
        inode->i_blocks++;
        inode->i_bytes -= 512;
    }
}
EXPORT_SYMBOL(__inode_add_bytes);

void inode_add_bytes(struct inode *inode, loff_t bytes)
{
    spin_lock(&inode->i_lock);
    __inode_add_bytes(inode, bytes);
    spin_unlock(&inode->i_lock);
}

void __inode_sub_bytes(struct inode *inode, loff_t bytes)
{
    inode->i_blocks -= bytes >> 9;
    bytes &= 511;
    if (inode->i_bytes < bytes) {
        inode->i_blocks--;
        inode->i_bytes += 512;
    }
    inode->i_bytes -= bytes;
}

void inode_sub_bytes(struct inode *inode, loff_t bytes)
{
    spin_lock(&inode->i_lock);
    __inode_sub_bytes(inode, bytes);
    spin_unlock(&inode->i_lock);
}

#ifndef INIT_STRUCT_STAT_PADDING
#  define INIT_STRUCT_STAT_PADDING(st) memset(&st, 0, sizeof(st))
#endif

static int cp_new_stat(struct kstat *stat, struct stat __user *statbuf)
{
    struct stat tmp;

    if (sizeof(tmp.st_dev) < 4 && !old_valid_dev(stat->dev))
        return -EOVERFLOW;
    if (sizeof(tmp.st_rdev) < 4 && !old_valid_dev(stat->rdev))
        return -EOVERFLOW;
#if BITS_PER_LONG == 32
    if (stat->size > MAX_NON_LFS)
        return -EOVERFLOW;
#endif

    INIT_STRUCT_STAT_PADDING(tmp);
    tmp.st_dev = new_encode_dev(stat->dev);
    tmp.st_ino = stat->ino;
    if (sizeof(tmp.st_ino) < sizeof(stat->ino) && tmp.st_ino != stat->ino)
        return -EOVERFLOW;
    tmp.st_mode = stat->mode;
    tmp.st_nlink = stat->nlink;
    if (tmp.st_nlink != stat->nlink)
        return -EOVERFLOW;
    SET_UID(tmp.st_uid, from_kuid_munged(current_user_ns(), stat->uid));
    SET_GID(tmp.st_gid, from_kgid_munged(current_user_ns(), stat->gid));
    tmp.st_rdev = new_encode_dev(stat->rdev);
    tmp.st_size = stat->size;
    tmp.st_atime = stat->atime.tv_sec;
    tmp.st_mtime = stat->mtime.tv_sec;
    tmp.st_ctime = stat->ctime.tv_sec;
#ifdef STAT_HAVE_NSEC
    tmp.st_atime_nsec = stat->atime.tv_nsec;
    tmp.st_mtime_nsec = stat->mtime.tv_nsec;
    tmp.st_ctime_nsec = stat->ctime.tv_nsec;
#endif
    tmp.st_blocks = stat->blocks;
    tmp.st_blksize = stat->blksize;
    memcpy(statbuf, &tmp, sizeof(tmp));
    return 0;
}

int cl_sys_newstat(const char *filename, struct stat *statbuf)
{
    struct kstat stat;
    int error = vfs_stat(filename, &stat);

    if (error)
        return error;
    return cp_new_stat(&stat, statbuf);
}

static int vfs_statx_path(struct path *path, int flags, struct kstat *stat,
              u32 request_mask)
{
    int error = vfs_getattr(path, stat, request_mask, flags);

    if (request_mask & STATX_MNT_ID_UNIQUE) {
        stat->mnt_id = real_mount(path->mnt)->mnt_id_unique;
        stat->result_mask |= STATX_MNT_ID_UNIQUE;
    } else {
        stat->mnt_id = real_mount(path->mnt)->mnt_id;
        stat->result_mask |= STATX_MNT_ID;
    }

    if (path_mounted(path))
        stat->attributes |= STATX_ATTR_MOUNT_ROOT;
    stat->attributes_mask |= STATX_ATTR_MOUNT_ROOT;

    /*
     * If this is a block device inode, override the filesystem
     * attributes with the block device specific parameters that need to be
     * obtained from the bdev backing inode.
     */
    if (S_ISBLK(stat->mode))
        bdev_statx(path, stat, request_mask);

    return error;
}

/**
 * vfs_statx - Get basic and extra attributes by filename
 * @dfd: A file descriptor representing the base dir for a relative filename
 * @filename: The name of the file of interest
 * @flags: Flags to control the query
 * @stat: The result structure to fill in.
 * @request_mask: STATX_xxx flags indicating what the caller wants
 *
 * This function is a wrapper around vfs_getattr().  The main difference is
 * that it uses a filename and base directory to determine the file location.
 * Additionally, the use of AT_SYMLINK_NOFOLLOW in flags will prevent a symlink
 * at the given name from being referenced.
 *
 * 0 will be returned on success, and a -ve error code if unsuccessful.
 */
static int vfs_statx(int dfd, struct filename *filename, int flags,
          struct kstat *stat, u32 request_mask)
{
    struct path path;
    unsigned int lookup_flags = getname_statx_lookup_flags(flags);
    int error;

    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH |
              AT_STATX_SYNC_TYPE))
        return -EINVAL;

retry:
    error = filename_lookup(dfd, filename, lookup_flags, &path, NULL);
    if (error)
        return error;
    error = vfs_statx_path(&path, flags, stat, request_mask);
    path_put(&path);
    if (retry_estale(error, lookup_flags)) {
        lookup_flags |= LOOKUP_REVAL;
        goto retry;
    }
    return error;
}

int vfs_fstatat(int dfd, const char __user *filename,
                struct kstat *stat, int flags)
{
    int ret;
    int statx_flags = flags | AT_NO_AUTOMOUNT;
    struct filename *name;

    /*
     * Work around glibc turning fstat() into fstatat(AT_EMPTY_PATH)
     *
     * If AT_EMPTY_PATH is set, we expect the common case to be that
     * empty path, and avoid doing all the extra pathname work.
     */
    if (flags == AT_EMPTY_PATH && vfs_empty_path(dfd, filename))
        return vfs_fstat(dfd, stat);

    name = getname_flags(filename, getname_statx_lookup_flags(statx_flags));
    ret = vfs_statx(dfd, name, statx_flags, stat, STATX_BASIC_STATS);
    putname(name);

    return ret;
}

/**
 * vfs_fstat - Get the basic attributes by file descriptor
 * @fd: The file descriptor referring to the file of interest
 * @stat: The result structure to fill in.
 *
 * This function is a wrapper around vfs_getattr().  The main difference is
 * that it uses a file descriptor to determine the file location.
 *
 * 0 will be returned on success, and a -ve error code if unsuccessful.
 */
int vfs_fstat(int fd, struct kstat *stat)
{
    struct fd f;
    int error;

#if 0
    f = fdget_raw(fd);
    if (!fd_file(f))
        return -EBADF;
    error = vfs_getattr(&fd_file(f)->f_path, stat, STATX_BASIC_STATS, 0);
    fdput(f);
    return error;
#endif
    PANIC("");
}

int getname_statx_lookup_flags(int flags)
{
    int lookup_flags = 0;

    if (!(flags & AT_SYMLINK_NOFOLLOW))
        lookup_flags |= LOOKUP_FOLLOW;
    if (!(flags & AT_NO_AUTOMOUNT))
        lookup_flags |= LOOKUP_AUTOMOUNT;
    if (flags & AT_EMPTY_PATH)
        lookup_flags |= LOOKUP_EMPTY;

    return lookup_flags;
}

/*
 * vfs_getattr - Get the enhanced basic attributes of a file
 * @path: The file of interest
 * @stat: Where to return the statistics
 * @request_mask: STATX_xxx flags indicating what the caller wants
 * @query_flags: Query mode (AT_STATX_SYNC_TYPE)
 *
 * Ask the filesystem for a file's attributes.  The caller must indicate in
 * request_mask and query_flags to indicate what they want.
 *
 * If the file is remote, the filesystem can be forced to update the attributes
 * from the backing store by passing AT_STATX_FORCE_SYNC in query_flags or can
 * suppress the update by passing AT_STATX_DONT_SYNC.
 *
 * Bits must have been set in request_mask to indicate which attributes the
 * caller wants retrieving.  Any such attribute not requested may be returned
 * anyway, but the value may be approximate, and, if remote, may not have been
 * synchronised with the server.
 *
 * 0 will be returned on success, and a -ve error code if unsuccessful.
 */
int vfs_getattr(const struct path *path, struct kstat *stat,
        u32 request_mask, unsigned int query_flags)
{
    int retval;

    if (WARN_ON_ONCE(query_flags & AT_GETATTR_NOSEC))
        return -EPERM;

    retval = security_inode_getattr(path);
    if (retval)
        return retval;
    return vfs_getattr_nosec(path, stat, request_mask, query_flags);
}

/**
 * vfs_getattr_nosec - getattr without security checks
 * @path: file to get attributes from
 * @stat: structure to return attributes in
 * @request_mask: STATX_xxx flags indicating what the caller wants
 * @query_flags: Query mode (AT_STATX_SYNC_TYPE)
 *
 * Get attributes without calling security_inode_getattr.
 *
 * Currently the only caller other than vfs_getattr is internal to the
 * filehandle lookup code, which uses only the inode number and returns no
 * attributes to any user.  Any other code probably wants vfs_getattr.
 */
int vfs_getattr_nosec(const struct path *path, struct kstat *stat,
              u32 request_mask, unsigned int query_flags)
{
    struct mnt_idmap *idmap;
    struct inode *inode = d_backing_inode(path->dentry);

    memset(stat, 0, sizeof(*stat));
    stat->result_mask |= STATX_BASIC_STATS;
    query_flags &= AT_STATX_SYNC_TYPE;

    /* allow the fs to override these if it really wants to */
    /* SB_NOATIME means filesystem supplies dummy atime value */
    if (inode->i_sb->s_flags & SB_NOATIME)
        stat->result_mask &= ~STATX_ATIME;

    /*
     * Note: If you add another clause to set an attribute flag, please
     * update attributes_mask below.
     */
    if (IS_AUTOMOUNT(inode))
        stat->attributes |= STATX_ATTR_AUTOMOUNT;

    if (IS_DAX(inode))
        stat->attributes |= STATX_ATTR_DAX;

    stat->attributes_mask |= (STATX_ATTR_AUTOMOUNT |
                  STATX_ATTR_DAX);

    idmap = mnt_idmap(path->mnt);
    if (inode->i_op->getattr)
        return inode->i_op->getattr(idmap, path, stat,
                        request_mask,
                        query_flags | AT_GETATTR_NOSEC);

    generic_fillattr(idmap, request_mask, inode, stat);
    return 0;
}

/**
 * generic_fillattr - Fill in the basic attributes from the inode struct
 * @idmap:      idmap of the mount the inode was found from
 * @request_mask:   statx request_mask
 * @inode:      Inode to use as the source
 * @stat:       Where to fill in the attributes
 *
 * Fill in the basic attributes in the kstat structure from data that's to be
 * found on the VFS inode structure.  This is the default if no getattr inode
 * operation is supplied.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then
 * take care to map the inode according to @idmap before filling in the
 * uid and gid filds. On non-idmapped mounts or if permission checking is to be
 * performed on the raw inode simply pass @nop_mnt_idmap.
 */
void generic_fillattr(struct mnt_idmap *idmap, u32 request_mask,
              struct inode *inode, struct kstat *stat)
{
    vfsuid_t vfsuid = i_uid_into_vfsuid(idmap, inode);
    vfsgid_t vfsgid = i_gid_into_vfsgid(idmap, inode);

    stat->dev = inode->i_sb->s_dev;
    stat->ino = inode->i_ino;
    stat->mode = inode->i_mode;
    stat->nlink = inode->i_nlink;
    stat->uid = vfsuid_into_kuid(vfsuid);
    stat->gid = vfsgid_into_kgid(vfsgid);
    stat->rdev = inode->i_rdev;
    stat->size = i_size_read(inode);
    stat->atime = inode_get_atime(inode);
    stat->mtime = inode_get_mtime(inode);
    stat->ctime = inode_get_ctime(inode);
    stat->blksize = i_blocksize(inode);
    stat->blocks = inode->i_blocks;

    if ((request_mask & STATX_CHANGE_COOKIE) && IS_I_VERSION(inode)) {
        stat->result_mask |= STATX_CHANGE_COOKIE;
        stat->change_cookie = inode_query_iversion(inode);
    }

}
