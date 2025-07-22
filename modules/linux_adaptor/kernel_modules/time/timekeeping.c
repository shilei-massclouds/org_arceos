#include <linux/printk.h>

#include "../adaptor.h"

ktime_t ktime_get(void)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}
