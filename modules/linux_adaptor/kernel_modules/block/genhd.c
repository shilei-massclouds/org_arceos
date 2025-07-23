#include <linux/blkdev.h>
#include <linux/backing-dev.h>

#include "blk-throttle.h"
#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"
#include "blk-cgroup.h"

#include "../adaptor.h"

/*
 * Can be deleted altogether. Later.
 *
 */
#define BLKDEV_MAJOR_HASH_SIZE 255
static struct blk_major_name {
    struct blk_major_name *next;
    int major;
    char name[16];
#ifdef CONFIG_BLOCK_LEGACY_AUTOLOAD
    void (*probe)(dev_t devt);
#endif
} *major_names[BLKDEV_MAJOR_HASH_SIZE];
static DEFINE_MUTEX(major_names_lock);
static DEFINE_SPINLOCK(major_names_spinlock);

/* index in the above - for now: assume no multimajor ranges */
static inline int major_to_index(unsigned major)
{
    return major % BLKDEV_MAJOR_HASH_SIZE;
}

/**
 * __register_blkdev - register a new block device
 *
 * @major: the requested major device number [1..BLKDEV_MAJOR_MAX-1]. If
 *         @major = 0, try to allocate any unused major number.
 * @name: the name of the new block device as a zero terminated string
 * @probe: pre-devtmpfs / pre-udev callback used to create disks when their
 *     pre-created device node is accessed. When a probe call uses
 *     add_disk() and it fails the driver must cleanup resources. This
 *     interface may soon be removed.
 *
 * The @name must be unique within the system.
 *
 * The return value depends on the @major input parameter:
 *
 *  - if a major device number was requested in range [1..BLKDEV_MAJOR_MAX-1]
 *    then the function returns zero on success, or a negative error code
 *  - if any unused major number was requested with @major = 0 parameter
 *    then the return value is the allocated major number in range
 *    [1..BLKDEV_MAJOR_MAX-1] or a negative error code otherwise
 *
 * See Documentation/admin-guide/devices.txt for the list of allocated
 * major numbers.
 *
 * Use register_blkdev instead for any new code.
 */
int __register_blkdev(unsigned int major, const char *name,
        void (*probe)(dev_t devt))
{
    struct blk_major_name **n, *p;
    int index, ret = 0;

    printk("%s: major(%u) name(%s)\n", __func__, major, name);
    mutex_lock(&major_names_lock);

    /* temporary */
    if (major == 0) {
        for (index = ARRAY_SIZE(major_names)-1; index > 0; index--) {
            if (major_names[index] == NULL)
                break;
        }

        if (index == 0) {
            printk("%s: failed to get major for %s\n",
                   __func__, name);
            ret = -EBUSY;
            goto out;
        }
        major = index;
        ret = major;
    }

    if (major >= BLKDEV_MAJOR_MAX) {
        pr_err("%s: major requested (%u) is greater than the maximum (%u) for %s\n",
               __func__, major, BLKDEV_MAJOR_MAX-1, name);

        ret = -EINVAL;
        goto out;
    }

    p = kmalloc(sizeof(struct blk_major_name), GFP_KERNEL);
    if (p == NULL) {
        ret = -ENOMEM;
        goto out;
    }

    p->major = major;
#ifdef CONFIG_BLOCK_LEGACY_AUTOLOAD
    p->probe = probe;
#endif
    strscpy(p->name, name, sizeof(p->name));
    p->next = NULL;
    index = major_to_index(major);

    spin_lock(&major_names_spinlock);
    for (n = &major_names[index]; *n; n = &(*n)->next) {
        if ((*n)->major == major)
            break;
    }
    if (!*n)
        *n = p;
    else
        ret = -EBUSY;
    spin_unlock(&major_names_spinlock);

    if (ret < 0) {
        printk("register_blkdev: cannot get major %u for %s\n",
               major, name);
        kfree(p);
    }
out:
    mutex_unlock(&major_names_lock);
    return ret;
}

struct gendisk *__alloc_disk_node(struct request_queue *q, int node_id,
        struct lock_class_key *lkclass)
{
    struct gendisk *disk;

    disk = kzalloc_node(sizeof(struct gendisk), GFP_KERNEL, node_id);
    if (!disk)
        return NULL;

    if (bioset_init(&disk->bio_split, BIO_POOL_SIZE, 0, 0))
        goto out_free_disk;

    disk->bdi = bdi_alloc(node_id);
    if (!disk->bdi)
        goto out_free_bioset;

    /* bdev_alloc() might need the queue, set before the first call */
    disk->queue = q;

    disk->part0 = bdev_alloc(disk, 0);
    if (!disk->part0)
        goto out_free_bdi;

    pr_err("%s: No impl. q(%lx)", __func__, q);
    PANIC("");

    return disk;

out_erase_part0:
    xa_erase(&disk->part_tbl, 0);
out_destroy_part_tbl:
    xa_destroy(&disk->part_tbl);
    disk->part0->bd_disk = NULL;
    bdev_drop(disk->part0);
out_free_bdi:
    bdi_put(disk->bdi);
out_free_bioset:
    bioset_exit(&disk->bio_split);
out_free_disk:
    kfree(disk);
    return NULL;
}

/*
 * Set disk capacity and notify if the size is not currently zero and will not
 * be set to zero.  Returns true if a uevent was sent, otherwise false.
 */
bool set_capacity_and_notify(struct gendisk *disk, sector_t size)
{
    sector_t capacity = get_capacity(disk);
    char *envp[] = { "RESIZE=1", NULL };

    set_capacity(disk, size);

    /*
     * Only print a message and send a uevent if the gendisk is user visible
     * and alive.  This avoids spamming the log and udev when setting the
     * initial capacity during probing.
     */
    if (size == capacity ||
        !disk_live(disk) ||
        (disk->flags & GENHD_FL_HIDDEN))
        return false;

    pr_info("%s: detected capacity change from %lld to %lld\n",
        disk->disk_name, capacity, size);

    /*
     * Historically we did not send a uevent for changes to/from an empty
     * device.
     */
    if (!capacity || !size)
        return false;
    kobject_uevent_env(&disk_to_dev(disk)->kobj, KOBJ_CHANGE, envp);
    return true;
}

void set_capacity(struct gendisk *disk, sector_t sectors)
{
    //bdev_set_nr_sectors(disk->part0, sectors);
    PANIC("");
}
