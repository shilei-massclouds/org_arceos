#include <linux/types.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/blk-mq.h>
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

int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set)
{
    printk("%s: NOTE: ---> Impl it.\n", __func__);
    return 0;
}

struct request_queue *blk_mq_init_queue(struct blk_mq_tag_set *set)
{
    printk("%s: NOTE: ---> Impl it.\n", __func__);
    return 0;
}
