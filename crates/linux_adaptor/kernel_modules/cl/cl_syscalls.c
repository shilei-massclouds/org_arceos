#include <linux/fs.h>

#include "../fs/internal.h"

#include "cl_syscalls.h"

int vfs_statx(int dfd, struct filename *filename, int flags,
	      struct kstat *stat, u32 request_mask);

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
    if (force_o_largefile())
        flags |= O_LARGEFILE;
    return do_sys_open(AT_FDCWD, filename, flags, mode);
}

int cl_sys_close(int fd)
{
}
