#include <linux/printk.h>
#include <linux/workqueue.h>
#include <linux/slab.h>

#include "booter.h"

struct workqueue_struct {
    struct list_head    pwqs;       /* WR: all pwqs of this wq */
    struct list_head    list;       /* PR: list of all workqueues */

    // There're some other members.
};

struct workqueue_struct *alloc_workqueue(const char *fmt,
                     unsigned int flags,
                     int max_active, ...)
{
    size_t tbl_size = 0;
    struct workqueue_struct *wq;

    printk("%s: ...\n", __func__);

    wq = kzalloc(sizeof(*wq) + tbl_size, GFP_KERNEL);
    if (!wq)
        return NULL;

    return wq;
}
