#include <linux/string.h>
#include <linux/time64.h>
#include <linux/rbtree.h>
#include <linux/fs.h>
#include <linux/pipe_fs_i.h>

#include "booter.h"

// Dummy defined in fs/splice.
const struct pipe_buf_operations default_pipe_buf_ops;

void get_random_bytes(void *buf, int nbytes)
{
    memset(buf, 1, nbytes);
}

time64_t ktime_get_real_seconds(void)
{
    return 0;
}

int ___ratelimit(struct ratelimit_state *rs, const char *func)
{
    log_error("%s: No impl.", __func__);
    return 0;
}

void __might_fault(const char *file, int line)
{
    log_error("%s: No impl.", __func__);
}
