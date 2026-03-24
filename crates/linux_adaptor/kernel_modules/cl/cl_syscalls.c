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
	return ksys_write(fd, buf, count);
}

int cl_sys_read(unsigned int fd, char *buf, size_t count)
{
	return ksys_read(fd, buf, count);
}

int cl_sys_unlink(const char *pathname)
{
	return do_unlinkat(AT_FDCWD, getname_kernel(pathname));
}

int cl_sys_rmdir(const char *pathname)
{
    PANIC("rmdir");
}
