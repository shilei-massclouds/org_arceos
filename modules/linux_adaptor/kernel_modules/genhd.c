#include <linux/types.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/blk-mq.h>
#include <linux/backing-dev.h>
#include <linux/ctype.h>

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

/*
 * Format the device name of the indicated disk into the supplied buffer and
 * return a pointer to that same buffer for convenience.
 */
char *disk_name(struct gendisk *hd, int partno, char *buf)
{
    if (!partno)
        snprintf(buf, BDEVNAME_SIZE, "%s", hd->disk_name);
    else if (isdigit(hd->disk_name[strlen(hd->disk_name)-1]))
        snprintf(buf, BDEVNAME_SIZE, "%sp%d", hd->disk_name, partno);
    else
        snprintf(buf, BDEVNAME_SIZE, "%s%d", hd->disk_name, partno);

    return buf;
}

const char *bdevname(struct block_device *bdev, char *buf)
{
    log_error("%s: No impl.\n", __func__);
    strcpy(buf, "vda");
    return buf;
    //return disk_name(bdev->bd_disk, bdev->bd_part->partno, buf);
}

int bdev_read_only(struct block_device *bdev)
{
    if (!bdev)
        return 0;
    if (bdev->bd_part == NULL) {
        log_error("%s: No bd_part.\n", __func__);
        return 0;
    }
    return bdev->bd_part->policy;
}
