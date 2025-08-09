#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/dirent.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/compat.h>
#include <linux/uaccess.h>

#include "../adaptor.h"

struct getdents_callback64 {
    struct dir_context ctx;
    struct linux_dirent64 __user * current_dir;
    int prev_reclen;
    int count;
    int error;
};

/*
 * POSIX says that a dirent name cannot contain NULL or a '/'.
 *
 * It's not 100% clear what we should really do in this case.
 * The filesystem is clearly corrupted, but returning a hard
 * error means that you now don't see any of the other names
 * either, so that isn't a perfect alternative.
 *
 * And if you return an error, what error do you use? Several
 * filesystems seem to have decided on EUCLEAN being the error
 * code for EFSCORRUPTED, and that may be the error to use. Or
 * just EIO, which is perhaps more obvious to users.
 *
 * In order to see the other file names in the directory, the
 * caller might want to make this a "soft" error: skip the
 * entry, and return the error at the end instead.
 *
 * Note that this should likely do a "memchr(name, 0, len)"
 * check too, since that would be filesystem corruption as
 * well. However, that case can't actually confuse user space,
 * which has to do a strlen() on the name anyway to find the
 * filename length, and the above "soft error" worry means
 * that it's probably better left alone until we have that
 * issue clarified.
 *
 * Note the PATH_MAX check - it's arbitrary but the real
 * kernel limit on a possible path component, not NAME_MAX,
 * which is the technical standard limit.
 */
int verify_dirent_name(const char *name, int len)
{
    if (len <= 0 || len >= PATH_MAX)
        return -EIO;
    if (memchr(name, '/', len))
        return -EIO;
    return 0;
}

static bool
filldir64(struct dir_context *ctx, const char *name, int namlen,
          loff_t offset, u64 ino, unsigned int d_type)
{
	struct linux_dirent64 __user *dirent, *prev;
	struct getdents_callback64 *buf =
		container_of(ctx, struct getdents_callback64, ctx);
	int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + namlen + 1,
		sizeof(u64));
	int prev_reclen;

	buf->error = verify_dirent_name(name, namlen);
	if (unlikely(buf->error))
		return false;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return false;
	prev_reclen = buf->prev_reclen;
	if (prev_reclen && signal_pending(current))
		return false;
	dirent = buf->current_dir;
	prev = (void __user *)dirent - prev_reclen;

	/* This might be 'dirent->d_off', but if so it will get overwritten */
	prev->d_off = offset;
	dirent->d_ino = ino;
	dirent->d_reclen = reclen;
	dirent->d_type = d_type;
    dirent->d_name[namlen] = 0;
    memcpy(dirent->d_name, name, namlen);

	buf->prev_reclen = reclen;
	buf->current_dir = (void __user *)dirent + reclen;
	buf->count -= reclen;
	return true;
}

int iterate_dir(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    int res = -ENOTDIR;

    if (!file->f_op->iterate_shared)
        goto out;

    res = security_file_permission(file, MAY_READ);
    if (res)
        goto out;

    res = fsnotify_file_perm(file, MAY_READ);
    if (res)
        goto out;

    res = down_read_killable(&inode->i_rwsem);
    if (res)
        goto out;

    res = -ENOENT;
    if (!IS_DEADDIR(inode)) {
        ctx->pos = file->f_pos;
        res = file->f_op->iterate_shared(file, ctx);
        file->f_pos = ctx->pos;
        fsnotify_access(file);
        file_accessed(file);
    }
    inode_unlock_shared(inode);
out:
    return res;
}

int cl_sys_getdents64(unsigned int fd,
                      struct linux_dirent64 *dirent,
                      unsigned int count)
{
    struct fd f;
    struct getdents_callback64 buf = {
        .ctx.actor = filldir64,
        .count = count,
        .current_dir = dirent
    };
    int error;

    f = fdget_pos(fd);
    if (!fd_file(f))
        return -EBADF;

    error = iterate_dir(fd_file(f), &buf.ctx);
    if (error >= 0)
        error = buf.error;
    if (buf.prev_reclen) {
        struct linux_dirent64 __user * lastdirent;
        typeof(lastdirent->d_off) d_off = buf.ctx.pos;

        lastdirent = (void __user *) buf.current_dir - buf.prev_reclen;
        lastdirent->d_off = d_off;
        error = count - buf.count;
    }
    fdput_pos(f);
    return error;
}
