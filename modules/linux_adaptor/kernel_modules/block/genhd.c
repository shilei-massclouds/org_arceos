#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/major.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include <linux/log2.h>
#include <linux/pm_runtime.h>
#include <linux/badblocks.h>
#include <linux/part_stat.h>
#include <linux/blktrace_api.h>

#include "blk-throttle.h"
#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"
#include "blk-cgroup.h"

#include "../adaptor.h"

/*
 * Unique, monotonically increasing sequential number associated with block
 * devices instances (i.e. incremented each time a device is attached).
 * Associating uevents with block devices in userspace is difficult and racy:
 * the uevent netlink socket is lossy, and on slow and overloaded systems has
 * a very high latency.
 * Block devices do not have exclusive owners in userspace, any process can set
 * one up (e.g. loop devices). Moreover, device names can be reused (e.g. loop0
 * can be reused again and again).
 * A userspace process setting up a block device and watching for its events
 * cannot thus reliably tell whether an event relates to the device it just set
 * up or another earlier instance with the same name.
 * This sequential number allows userspace processes to solve this problem, and
 * uniquely associate an uevent to the lifetime to a device.
 */
static atomic64_t diskseq;

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

static struct attribute *disk_attrs[] = {
#if 0
    &dev_attr_range.attr,
    &dev_attr_ext_range.attr,
    &dev_attr_removable.attr,
    &dev_attr_hidden.attr,
    &dev_attr_ro.attr,
    &dev_attr_size.attr,
    &dev_attr_alignment_offset.attr,
    &dev_attr_discard_alignment.attr,
    &dev_attr_capability.attr,
    &dev_attr_stat.attr,
    &dev_attr_inflight.attr,
    &dev_attr_badblocks.attr,
    &dev_attr_events.attr,
    &dev_attr_events_async.attr,
    &dev_attr_events_poll_msecs.attr,
    &dev_attr_diskseq.attr,
    &dev_attr_partscan.attr,
#endif
#ifdef CONFIG_FAIL_MAKE_REQUEST
    &dev_attr_fail.attr,
#endif
#ifdef CONFIG_FAIL_IO_TIMEOUT
    &dev_attr_fail_timeout.attr,
#endif
    NULL
};

static umode_t disk_visible(struct kobject *kobj, struct attribute *a, int n)
{
    PANIC("");
}

/**
 * disk_release - releases all allocated resources of the gendisk
 * @dev: the device representing this disk
 *
 * This function releases all allocated resources of the gendisk.
 *
 * Drivers which used __device_add_disk() have a gendisk with a request_queue
 * assigned. Since the request_queue sits on top of the gendisk for these
 * drivers we also call blk_put_queue() for them, and we expect the
 * request_queue refcount to reach 0 at this point, and so the request_queue
 * will also be freed prior to the disk.
 *
 * Context: can sleep
 */
static void disk_release(struct device *dev)
{
    PANIC("");
}

static struct attribute_group disk_attr_group = {
    .attrs = disk_attrs,
    .is_visible = disk_visible,
};

static const struct attribute_group *disk_attr_groups[] = {
    &disk_attr_group,
#ifdef CONFIG_BLK_DEV_IO_TRACE
    &blk_trace_attr_group,
#endif
#ifdef CONFIG_BLK_DEV_INTEGRITY
    &blk_integrity_attr_group,
#endif
    NULL
};

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

static int block_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
    const struct gendisk *disk = dev_to_disk(dev);

    return add_uevent_var(env, "DISKSEQ=%llu", disk->diskseq);
}

const struct class block_class = {
    .name       = "block",
    .dev_uevent = block_uevent,
};

static char *block_devnode(const struct device *dev, umode_t *mode,
               kuid_t *uid, kgid_t *gid)
{
    struct gendisk *disk = dev_to_disk(dev);

    if (disk->fops->devnode)
        return disk->fops->devnode(disk, mode);
    return NULL;
}

const struct device_type disk_type = {
    .name       = "disk",
    .groups     = disk_attr_groups,
    .release    = disk_release,
    .devnode    = block_devnode,
};

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

    disk->node_id = node_id;
    mutex_init(&disk->open_mutex);
    xa_init(&disk->part_tbl);
    if (xa_insert(&disk->part_tbl, 0, disk->part0, GFP_KERNEL))
        goto out_destroy_part_tbl;

    if (blkcg_init_disk(disk))
        goto out_erase_part0;

    disk_init_zone_resources(disk);
    //rand_initialize_disk(disk);
    disk_to_dev(disk)->class = &block_class;
    disk_to_dev(disk)->type = &disk_type;
    device_initialize(disk_to_dev(disk));
    inc_diskseq(disk);
    q->disk = disk;
    lockdep_init_map(&disk->lockdep_map, "(bio completion)", lkclass, 0);
#ifdef CONFIG_BLOCK_HOLDER_DEPRECATED
    INIT_LIST_HEAD(&disk->slave_bdevs);
#endif
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

void inc_diskseq(struct gendisk *disk)
{
    disk->diskseq = atomic64_inc_return(&diskseq);
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
    bdev_set_nr_sectors(disk->part0, sectors);
}
