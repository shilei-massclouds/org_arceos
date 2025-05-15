#include <linux/types.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/blk-mq.h>
#include <linux/backing-dev.h>

#include "booter.h"

int register_blkdev(unsigned int major, const char *name)
{
    printk("%s: major [%d] name [%s]\n", __func__, major, name);
    return 0;
}

struct gendisk *__alloc_disk_node(int minors, int node_id)
{
    struct gendisk *disk;
    struct disk_part_tbl *ptbl;

    if (minors > DISK_MAX_PARTS) {
        printk(KERN_ERR
            "block: can't allocate more than %d partitions\n",
            DISK_MAX_PARTS);
        minors = DISK_MAX_PARTS;
    }

    disk = kzalloc_node(sizeof(struct gendisk), GFP_KERNEL, node_id);

    printk("%s: impl it.\n", __func__);
    return disk;
}

struct gendisk *cl_disk;

void device_add_disk(struct device *parent, struct gendisk *disk,
             const struct attribute_group **groups)

{
    struct request_queue *q = disk->queue;
    printk("+++++++++++++++++++++++++++++++++++++++++\n");
    //printk("%s: q (%lx)(%lx).\n", __func__, q, q->mq_ops);
    cl_disk = disk;
    //__device_add_disk(parent, disk, groups, true);
    printk("%s: No impl.\n", __func__);
}
