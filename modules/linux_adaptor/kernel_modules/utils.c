#include <linux/string.h>
#include <linux/time64.h>
#include <linux/rbtree.h>

#include "booter.h"

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

