#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/syscalls.h>

#include "../fs/internal.h"

#include "adaptor.h"

int vfs_statx(int dfd, struct filename *filename, int flags,
	      struct kstat *stat, u32 request_mask);

int filp_flush(struct file *filp, fl_owner_t id);
off_t ksys_lseek(unsigned int fd, off_t offset, unsigned int whence);
extern inline loff_t *file_ppos(struct file *file);

int cl_sys_mkdir(const char *pathname, umode_t mode)
{
    return do_mkdirat(AT_FDCWD, getname_kernel(pathname), mode);
}

int cl_sys_exist(const char *path,
                 unsigned long *r_type,
                 unsigned long *r_size)
{
	int ret;
	struct filename *name;
	struct kstat stat;

	name = getname_kernel(path);
	ret = vfs_statx(AT_FDCWD, name, AT_NO_AUTOMOUNT, &stat, STATX_BASIC_STATS);
	putname(name);

    if (!ret) {
        *r_type = S_DT(stat.mode);
        *r_size = stat.size;
    }
	return ret;
}

int cl_sys_open(const char *filename, int flags, umode_t mode)
{
    int fd;
	struct open_flags op;
	struct filename *tmp;
	struct open_how how = build_open_how(flags|O_LARGEFILE, mode);

	fd = build_open_flags(&how, &op);
	if (fd)
		return fd;

	tmp = getname_kernel(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(how.flags);
	if (fd >= 0) {
		struct file *f = do_filp_open(AT_FDCWD, tmp, &op);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fd_install(fd, f);
		}
	}
	putname(tmp);
	return fd;
}

int cl_sys_close(int fd)
{
	int retval;
	struct file *file;

	file = file_close_fd(fd);
	if (!file)
		return -EBADF;

	retval = filp_flush(file, current->files);

	/*
	 * We're returning to user space. Don't bother
	 * with any delayed fput() cases.
	 */
	__fput_sync(file);

	/* can't restart close syscall because file table entry was cleared */
	if (unlikely(retval == -ERESTARTSYS ||
		     retval == -ERESTARTNOINTR ||
		     retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;
}

int cl_sys_truncate(const char *pathname, long length)
{
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	struct path path;
	int error;

	if (length < 0)	/* sorry, but loff_t says... */
		return -EINVAL;

retry:
    error = kern_path(pathname, lookup_flags, &path);

	if (!error) {
		error = vfs_truncate(&path, length);
		path_put(&path);
	}
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

int cl_sys_lseek(unsigned int fd, off_t offset, unsigned int whence)
{
	return ksys_lseek(fd, offset, whence);
}

int cl_sys_write(unsigned int fd, const char *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (fd_file(f)) {
		loff_t pos, *ppos = file_ppos(fd_file(f));
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = kernel_write(fd_file(f), buf, count, ppos);
		if (ret >= 0 && ppos)
			fd_file(f)->f_pos = pos;
		fdput_pos(f);
	}

	return ret;
}

int cl_sys_read(unsigned int fd, char *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (fd_file(f)) {
		loff_t pos, *ppos = file_ppos(fd_file(f));
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = kernel_read(fd_file(f), buf, count, ppos);
		if (ret >= 0 && ppos)
			fd_file(f)->f_pos = pos;
		fdput_pos(f);
	}
	return ret;
}

int cl_sys_unlink(const char *pathname)
{
	return do_unlinkat(AT_FDCWD, getname_kernel(pathname));
}

int cl_sys_rmdir(const char *pathname)
{
    PANIC("rmdir");
}

/*
 * getdents64
 */

int verify_dirent_name(const char *name, int len);

struct getdents_callback64_kernel {
	struct dir_context ctx;
	struct linux_dirent64 *current_dir;
	int prev_reclen;
	int count;
	int error;
};

static bool
filldir64_kernel(struct dir_context *ctx,
                 const char *name,
                 int namlen,
                 loff_t offset,
                 u64 ino,
                 unsigned int d_type)
{
	struct linux_dirent64 *dirent, *prev;
	struct getdents_callback64_kernel *buf =
		container_of(ctx, struct getdents_callback64_kernel, ctx);
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
	prev = (void *)dirent - prev_reclen;

	/* This might be 'dirent->d_off', but if so it will get overwritten */
	prev->d_off = offset;
	dirent->d_ino = ino;
	dirent->d_reclen = reclen;
	dirent->d_type = d_type;
    strncpy(dirent->d_name, name, namlen);

	buf->prev_reclen = reclen;
	buf->current_dir = (void *)dirent + reclen;
	buf->count -= reclen;
	return true;
}

int cl_sys_getdents64(unsigned int fd,
                      struct linux_dirent64 *dirent,
                      unsigned int count)
{
	struct fd f;
	struct getdents_callback64_kernel buf = {
		.ctx.actor = filldir64_kernel,
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
		struct linux_dirent64 *lastdirent;
		typeof(lastdirent->d_off) d_off = buf.ctx.pos;

		lastdirent = (void *) buf.current_dir - buf.prev_reclen;

        lastdirent->d_off = d_off;
        error = count - buf.count;
	}
	fdput_pos(f);
	return error;
}
