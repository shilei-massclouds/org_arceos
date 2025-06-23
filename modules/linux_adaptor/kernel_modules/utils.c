#include <linux/string.h>
#include <linux/time64.h>
#include <linux/rbtree.h>

#include "booter.h"

void get_random_bytes(void *buf, int nbytes)
{
    memset(buf, 1, nbytes);
}

void rb_insert_color(struct rb_node *node, struct rb_root *root)
{
    log_error("%s: impl it. NEED rbtree! \n", __func__);
}

time64_t ktime_get_real_seconds(void)
{
    return 0;
}
