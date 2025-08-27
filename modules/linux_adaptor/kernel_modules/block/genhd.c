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

static struct kobject *block_depr;

/* for extended dynamic devt allocation, currently only one major is used */
#define NR_EXT_DEVT     (1 << MINORBITS)
static DEFINE_IDA(ext_devt_ida);

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

int disk_scan_partitions(struct gendisk *disk, blk_mode_t mode)
{
    struct file *file;
    int ret = 0;

    if (!disk_has_partscan(disk))
        return -EINVAL;
    if (disk->open_partitions)
        return -EBUSY;

#if 0
    /*
     * If the device is opened exclusively by current thread already, it's
     * safe to scan partitons, otherwise, use bd_prepare_to_claim() to
     * synchronize with other exclusive openers and other partition
     * scanners.
     */
    if (!(mode & BLK_OPEN_EXCL)) {
        ret = bd_prepare_to_claim(disk->part0, disk_scan_partitions,
                      NULL);
        if (ret)
            return ret;
    }
#endif

    pr_notice("%s: No impl.", __func__);
    return 0;
}

/**
 * device_add_disk - add disk information to kernel list
 * @parent: parent device for the disk
 * @disk: per-device partitioning information
 * @groups: Additional per-device sysfs groups
 *
 * This function registers the partitioning information in @disk
 * with the kernel.
 */
int __must_check device_add_disk(struct device *parent, struct gendisk *disk,
                 const struct attribute_group **groups)

{
    struct device *ddev = disk_to_dev(disk);
    int ret;

    /* Only makes sense for bio-based to set ->poll_bio */
    if (queue_is_mq(disk->queue) && disk->fops->poll_bio)
        return -EINVAL;

#if 0
    /*
     * The disk queue should now be all set with enough information about
     * the device for the elevator code to pick an adequate default
     * elevator if one is needed, that is, for devices requesting queue
     * registration.
     */
    elevator_init_mq(disk->queue);
#endif

    /* Mark bdev as having a submit_bio, if needed */
    if (disk->fops->submit_bio)
        bdev_set_flag(disk->part0, BD_HAS_SUBMIT_BIO);

    /*
     * If the driver provides an explicit major number it also must provide
     * the number of minors numbers supported, and those will be used to
     * setup the gendisk.
     * Otherwise just allocate the device numbers for both the whole device
     * and all partitions from the extended dev_t space.
     */
    ret = -EINVAL;
    if (disk->major) {
        if (WARN_ON(!disk->minors))
            goto out_exit_elevator;

        if (disk->minors > DISK_MAX_PARTS) {
            pr_err("block: can't allocate more than %d partitions\n",
                DISK_MAX_PARTS);
            disk->minors = DISK_MAX_PARTS;
        }
        if (disk->first_minor > MINORMASK ||
            disk->minors > MINORMASK + 1 ||
            disk->first_minor + disk->minors > MINORMASK + 1)
            goto out_exit_elevator;
    } else {
        if (WARN_ON(disk->minors))
            goto out_exit_elevator;

        ret = blk_alloc_ext_minor();
        if (ret < 0)
            goto out_exit_elevator;
        disk->major = BLOCK_EXT_MAJOR;
        disk->first_minor = ret;
    }

    /* delay uevents, until we scanned partition table */
    dev_set_uevent_suppress(ddev, 1);

    ddev->parent = parent;
    ddev->groups = groups;
    dev_set_name(ddev, "%s", disk->disk_name);
    if (!(disk->flags & GENHD_FL_HIDDEN))
        ddev->devt = MKDEV(disk->major, disk->first_minor);
    printk("%s: major(%u) minor(%u,%u)\n", __func__, disk->major, disk->first_minor, disk->minors);
    ret = device_add(ddev);
    if (ret)
        goto out_free_ext_minor;

#if 0
    ret = disk_alloc_events(disk);
    if (ret)
        goto out_device_del;

    ret = sysfs_create_link(block_depr, &ddev->kobj,
                kobject_name(&ddev->kobj));
    if (ret)
        goto out_device_del;

    /*
     * avoid probable deadlock caused by allocating memory with
     * GFP_KERNEL in runtime_resume callback of its all ancestor
     * devices
     */
    pm_runtime_set_memalloc_noio(ddev, true);

    disk->part0->bd_holder_dir =
        kobject_create_and_add("holders", &ddev->kobj);
    if (!disk->part0->bd_holder_dir) {
        ret = -ENOMEM;
        goto out_del_block_link;
    }
    disk->slave_dir = kobject_create_and_add("slaves", &ddev->kobj);
    if (!disk->slave_dir) {
        ret = -ENOMEM;
        goto out_put_holder_dir;
    }

    ret = blk_register_queue(disk);
    if (ret)
        goto out_put_slave_dir;
#endif

    if (!(disk->flags & GENHD_FL_HIDDEN)) {
        ret = bdi_register(disk->bdi, "%u:%u",
                   disk->major, disk->first_minor);
        if (ret)
            goto out_unregister_queue;
        bdi_set_owner(disk->bdi, ddev);
        /*
        ret = sysfs_create_link(&ddev->kobj,
                    &disk->bdi->dev->kobj, "bdi");
        if (ret)
            goto out_unregister_bdi;
        */

        /* Make sure the first partition scan will be proceed */
        if (get_capacity(disk) && disk_has_partscan(disk))
            set_bit(GD_NEED_PART_SCAN, &disk->state);

        bdev_add(disk->part0, ddev->devt);
        if (get_capacity(disk))
            disk_scan_partitions(disk, BLK_OPEN_READ);

        /*
         * Announce the disk and partitions after all partitions are
         * created. (for hidden disks uevents remain suppressed forever)
         */
        dev_set_uevent_suppress(ddev, 0);
        //disk_uevent(disk, KOBJ_ADD);
    } else {
        PANIC("GENHD_FL_HIDDEN");
    }

    blk_apply_bdi_limits(disk->bdi, &disk->queue->limits);
    //disk_add_events(disk);
    set_bit(GD_ADDED, &disk->state);
    return 0;

out_unregister_bdi:
    if (!(disk->flags & GENHD_FL_HIDDEN))
        bdi_unregister(disk->bdi);
out_unregister_queue:
    blk_unregister_queue(disk);
    rq_qos_exit(disk->queue);
out_put_slave_dir:
    kobject_put(disk->slave_dir);
    disk->slave_dir = NULL;
out_put_holder_dir:
    kobject_put(disk->part0->bd_holder_dir);
out_del_block_link:
    //sysfs_remove_link(block_depr, dev_name(ddev));
    //pm_runtime_set_memalloc_noio(ddev, false);
out_device_del:
    device_del(ddev);
out_free_ext_minor:
    if (disk->major == BLOCK_EXT_MAJOR)
        blk_free_ext_minor(disk->first_minor);
out_exit_elevator:
    if (disk->queue->elevator)
        elevator_exit(disk->queue);
    return ret;
}

int blk_alloc_ext_minor(void)
{
    int idx;

    idx = ida_alloc_range(&ext_devt_ida, 0, NR_EXT_DEVT - 1, GFP_KERNEL);
    if (idx == -ENOSPC)
        return -EBUSY;
    return idx;
}

void blk_free_ext_minor(unsigned int minor)
{
    ida_free(&ext_devt_ida, minor);
}

void blk_request_module(dev_t devt)
{
    pr_err("%s: No impl.", __func__);
}

unsigned int part_in_flight(struct block_device *part)
{
    unsigned int inflight = 0;
    int cpu;

    for_each_possible_cpu(cpu) {
        inflight += part_stat_local_read_cpu(part, in_flight[0], cpu) +
                part_stat_local_read_cpu(part, in_flight[1], cpu);
    }
    if ((int)inflight < 0)
        inflight = 0;

    return inflight;
}
