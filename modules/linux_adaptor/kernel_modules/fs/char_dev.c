#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/seq_file.h>

#include <linux/kobject.h>
#include <linux/kobj_map.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/backing-dev.h>
#include <linux/tty.h>

#include "internal.h"
#include "../adaptor.h"

static struct kobj_map *cdev_map __ro_after_init;

static DEFINE_MUTEX(chrdevs_lock);

#define CHRDEV_MAJOR_HASH_SIZE 255

static struct char_device_struct {
    struct char_device_struct *next;
    unsigned int major;
    unsigned int baseminor;
    int minorct;
    char name[64];
    struct cdev *cdev;      /* will die */
} *chrdevs[CHRDEV_MAJOR_HASH_SIZE];

/* index in the above */
static inline int major_to_index(unsigned major)
{
    return major % CHRDEV_MAJOR_HASH_SIZE;
}

static DEFINE_SPINLOCK(cdev_lock);

static struct kobject *cdev_get(struct cdev *p)
{
    struct module *owner = p->owner;
    struct kobject *kobj;

    if (!try_module_get(owner))
        return NULL;
    kobj = kobject_get_unless_zero(&p->kobj);
    if (!kobj)
        module_put(owner);
    return kobj;
}

static struct kobject *exact_match(dev_t dev, int *part, void *data)
{
    struct cdev *p = data;
    return &p->kobj;
}

static int exact_lock(dev_t dev, void *data)
{
    struct cdev *p = data;
    return cdev_get(p) ? 0 : -1;
}

void cd_forget(struct inode *inode)
{
    spin_lock(&cdev_lock);
    list_del_init(&inode->i_devices);
    inode->i_cdev = NULL;
    inode->i_mapping = &inode->i_data;
    spin_unlock(&cdev_lock);
}

void cdev_put(struct cdev *p)
{
    if (p) {
        struct module *owner = p->owner;
        kobject_put(&p->kobj);
        module_put(owner);
    }
}

static int find_dynamic_major(void)
{
    int i;
    struct char_device_struct *cd;

    for (i = ARRAY_SIZE(chrdevs)-1; i >= CHRDEV_MAJOR_DYN_END; i--) {
        if (chrdevs[i] == NULL)
            return i;
    }

    for (i = CHRDEV_MAJOR_DYN_EXT_START;
         i >= CHRDEV_MAJOR_DYN_EXT_END; i--) {
        for (cd = chrdevs[major_to_index(i)]; cd; cd = cd->next)
            if (cd->major == i)
                break;

        if (cd == NULL)
            return i;
    }

    return -EBUSY;
}

/*
 * Register a single major with a specified minor range.
 *
 * If major == 0 this function will dynamically allocate an unused major.
 * If major > 0 this function will attempt to reserve the range of minors
 * with given major.
 *
 */
static struct char_device_struct *
__register_chrdev_region(unsigned int major, unsigned int baseminor,
               int minorct, const char *name)
{
    struct char_device_struct *cd, *curr, *prev = NULL;
    int ret;
    int i;

    if (major >= CHRDEV_MAJOR_MAX) {
        pr_err("CHRDEV \"%s\" major requested (%u) is greater than the maximum (%u)\n",
               name, major, CHRDEV_MAJOR_MAX-1);
        return ERR_PTR(-EINVAL);
    }

    if (minorct > MINORMASK + 1 - baseminor) {
        pr_err("CHRDEV \"%s\" minor range requested (%u-%u) is out of range of maximum range (%u-%u) for a single major\n",
            name, baseminor, baseminor + minorct - 1, 0, MINORMASK);
        return ERR_PTR(-EINVAL);
    }

    cd = kzalloc(sizeof(struct char_device_struct), GFP_KERNEL);
    if (cd == NULL)
        return ERR_PTR(-ENOMEM);

    mutex_lock(&chrdevs_lock);

    if (major == 0) {
        ret = find_dynamic_major();
        if (ret < 0) {
            pr_err("CHRDEV \"%s\" dynamic allocation region is full\n",
                   name);
            goto out;
        }
        major = ret;
    }

    ret = -EBUSY;
    i = major_to_index(major);
    for (curr = chrdevs[i]; curr; prev = curr, curr = curr->next) {
        if (curr->major < major)
            continue;

        if (curr->major > major)
            break;

        if (curr->baseminor + curr->minorct <= baseminor)
            continue;

        if (curr->baseminor >= baseminor + minorct)
            break;

        goto out;
    }

    cd->major = major;
    cd->baseminor = baseminor;
    cd->minorct = minorct;
    strscpy(cd->name, name, sizeof(cd->name));

    if (!prev) {
        cd->next = curr;
        chrdevs[i] = cd;
    } else {
        cd->next = prev->next;
        prev->next = cd;
    }

    mutex_unlock(&chrdevs_lock);
    return cd;
out:
    mutex_unlock(&chrdevs_lock);
    kfree(cd);
    return ERR_PTR(ret);
}

/**
 * alloc_chrdev_region() - register a range of char device numbers
 * @dev: output parameter for first assigned number
 * @baseminor: first of the requested range of minor numbers
 * @count: the number of minor numbers required
 * @name: the name of the associated device or driver
 *
 * Allocates a range of char device numbers.  The major number will be
 * chosen dynamically, and returned (along with the first minor number)
 * in @dev.  Returns zero or a negative error code.
 */
int alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count,
            const char *name)
{
    struct char_device_struct *cd;
    cd = __register_chrdev_region(0, baseminor, count, name);
    if (IS_ERR(cd))
        return PTR_ERR(cd);
    *dev = MKDEV(cd->major, cd->baseminor);
    return 0;
}

static void cdev_purge(struct cdev *cdev)
{
    spin_lock(&cdev_lock);
    while (!list_empty(&cdev->list)) {
        struct inode *inode;
        inode = container_of(cdev->list.next, struct inode, i_devices);
        list_del_init(&inode->i_devices);
        inode->i_cdev = NULL;
    }
    spin_unlock(&cdev_lock);
}

static void cdev_default_release(struct kobject *kobj)
{
    struct cdev *p = container_of(kobj, struct cdev, kobj);
    struct kobject *parent = kobj->parent;

    cdev_purge(p);
    kobject_put(parent);
}

static struct kobj_type ktype_cdev_default = {
    .release    = cdev_default_release,
};

/**
 * cdev_init() - initialize a cdev structure
 * @cdev: the structure to initialize
 * @fops: the file_operations for this device
 *
 * Initializes @cdev, remembering @fops, making it ready to add to the
 * system with cdev_add().
 */
void cdev_init(struct cdev *cdev, const struct file_operations *fops)
{
    memset(cdev, 0, sizeof *cdev);
    INIT_LIST_HEAD(&cdev->list);
    kobject_init(&cdev->kobj, &ktype_cdev_default);
    cdev->ops = fops;
}

/**
 * cdev_device_add() - add a char device and it's corresponding
 *  struct device, linkink
 * @dev: the device structure
 * @cdev: the cdev structure
 *
 * cdev_device_add() adds the char device represented by @cdev to the system,
 * just as cdev_add does. It then adds @dev to the system using device_add
 * The dev_t for the char device will be taken from the struct device which
 * needs to be initialized first. This helper function correctly takes a
 * reference to the parent device so the parent will not get released until
 * all references to the cdev are released.
 *
 * This helper uses dev->devt for the device number. If it is not set
 * it will not add the cdev and it will be equivalent to device_add.
 *
 * This function should be used whenever the struct cdev and the
 * struct device are members of the same structure whose lifetime is
 * managed by the struct device.
 *
 * NOTE: Callers must assume that userspace was able to open the cdev and
 * can call cdev fops callbacks at any time, even if this function fails.
 */
int cdev_device_add(struct cdev *cdev, struct device *dev)
{
    int rc = 0;

    if (dev->devt) {
        cdev_set_parent(cdev, &dev->kobj);

        rc = cdev_add(cdev, dev->devt, 1);
        if (rc)
            return rc;
    }

    rc = device_add(dev);
    if (rc && dev->devt)
        cdev_del(cdev);

    return rc;
}

/**
 * cdev_add() - add a char device to the system
 * @p: the cdev structure for the device
 * @dev: the first device number for which this device is responsible
 * @count: the number of consecutive minor numbers corresponding to this
 *         device
 *
 * cdev_add() adds the device represented by @p to the system, making it
 * live immediately.  A negative error code is returned on failure.
 */
int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
    int error;

    p->dev = dev;
    p->count = count;

    if (WARN_ON(dev == WHITEOUT_DEV)) {
        error = -EBUSY;
        goto err;
    }

    error = kobj_map(cdev_map, dev, count, NULL,
             exact_match, exact_lock, p);
    if (error)
        goto err;

    kobject_get(p->kobj.parent);

    return 0;

err:
    kfree_const(p->kobj.name);
    p->kobj.name = NULL;
    return error;
}

static void cdev_unmap(dev_t dev, unsigned count)
{
    kobj_unmap(cdev_map, dev, count);
}

/**
 * cdev_del() - remove a cdev from the system
 * @p: the cdev structure to be removed
 *
 * cdev_del() removes @p from the system, possibly freeing the structure
 * itself.
 *
 * NOTE: This guarantees that cdev device will no longer be able to be
 * opened, however any cdevs already open will remain and their fops will
 * still be callable even after cdev_del returns.
 */
void cdev_del(struct cdev *p)
{
    cdev_unmap(p->dev, p->count);
    kobject_put(&p->kobj);
}

/**
 * cdev_set_parent() - set the parent kobject for a char device
 * @p: the cdev structure
 * @kobj: the kobject to take a reference to
 *
 * cdev_set_parent() sets a parent kobject which will be referenced
 * appropriately so the parent is not freed before the cdev. This
 * should be called before cdev_add.
 */
void cdev_set_parent(struct cdev *p, struct kobject *kobj)
{
    WARN_ON(!kobj->state_initialized);
    p->kobj.parent = kobj;
}

static struct kobject *base_probe(dev_t dev, int *part, void *data)
{
    if (request_module("char-major-%d-%d", MAJOR(dev), MINOR(dev)) > 0)
        /* Make old-style 2.4 aliases work */
        request_module("char-major-%d", MAJOR(dev));
    return NULL;
}

void __init chrdev_init(void)
{
    cdev_map = kobj_map_init(base_probe, &chrdevs_lock);
}
