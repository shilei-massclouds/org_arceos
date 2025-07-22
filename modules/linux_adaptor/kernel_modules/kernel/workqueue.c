#include <linux/slab.h>

struct workqueue_struct {
};

__printf(1, 4)
struct workqueue_struct *alloc_workqueue(const char *fmt,
                     unsigned int flags,
                     int max_active, ...)
{
    pr_err("%s: No impl.\n", __func__);
    return kzalloc(sizeof(struct workqueue_struct), GFP_KERNEL);
}
