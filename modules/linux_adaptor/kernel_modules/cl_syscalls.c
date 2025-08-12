#include <linux/fs.h>

#include "cl_syscalls.h"

int cl_sys_exist(const char *path,
                 unsigned long *r_type,
                 unsigned long *r_size)
{
    struct stat buf;
    int err = cl_sys_newstat(path, &buf);
    if (err < 0) {
        return err;
    }

    *r_type = S_DT(buf.st_mode);
    *r_size = buf.st_size;
    return 0;
}
