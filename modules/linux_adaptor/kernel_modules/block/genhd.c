#include <linux/blkdev.h>

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
