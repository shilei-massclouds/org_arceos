#include <linux/printk.h>

#include "../adaptor.h"

ktime_t ktime_get(void)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

void ktime_get_coarse_real_ts64(struct timespec64 *ts)
{
    pr_err("%s: No impl.", __func__);
}
