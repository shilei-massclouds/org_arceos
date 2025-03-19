#include <linux/types.h>
#include <linux/backing-dev.h>

#include "booter.h"

struct backing_dev_info *bdi_alloc(int node_id)
{
    struct backing_dev_info *bdi;

    bdi = kzalloc_node(sizeof(*bdi), GFP_KERNEL, node_id);
    if (!bdi)
        return NULL;

    /*
    if (bdi_init(bdi)) {
        kfree(bdi);
        return NULL;
    }
    */
    printk("%s: No bdi_init.\n", __func__);
    return bdi;
}
