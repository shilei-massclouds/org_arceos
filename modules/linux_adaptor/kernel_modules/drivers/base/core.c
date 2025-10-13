#include <linux/acpi.h>
#include <linux/blkdev.h>
#include <linux/cleanup.h>
#include <linux/cpufreq.h>
#include <linux/device.h>
#include <linux/dma-map-ops.h> /* for dma_default_coherent */
#include <linux/err.h>
#include <linux/fwnode.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/pm_runtime.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string_helpers.h>
#include <linux/swiotlb.h>
#include <linux/sysfs.h>

#include "base.h"
#include "physical_location.h"
#include "power/power.h"
#include "../adaptor.h"

#define FW_DEVLINK_FLAGS_PERMISSIVE (DL_FLAG_INFERRED | \
                     DL_FLAG_SYNC_STATE_ONLY)
#define FW_DEVLINK_FLAGS_ON     (DL_FLAG_INFERRED | \
                     DL_FLAG_AUTOPROBE_CONSUMER)
#define FW_DEVLINK_FLAGS_RPM        (FW_DEVLINK_FLAGS_ON | \
                     DL_FLAG_PM_RUNTIME)

#define DL_MARKER_FLAGS     (DL_FLAG_INFERRED | \
                 DL_FLAG_CYCLE | \
                 DL_FLAG_MANAGED)
static inline bool device_link_flag_is_sync_state_only(u32 flags)
{
    return (flags & ~DL_MARKER_FLAGS) == DL_FLAG_SYNC_STATE_ONLY;
}

/* /sys/devices/ */
struct kset *devices_kset;

static u32 fw_devlink_flags = FW_DEVLINK_FLAGS_RPM;
static bool fw_devlink_best_effort;
static bool fw_devlink_drv_reg_done;

static DEFINE_MUTEX(fwnode_link_lock);
static DEFINE_MUTEX(gdp_mutex);

/* Device links support end. */

static struct kobject *dev_kobj;

/* Device links support. */
static LIST_HEAD(deferred_sync);

/* /sys/dev/char */
static struct kobject *sysfs_dev_char_kobj;

/* /sys/dev/block */
static struct kobject *sysfs_dev_block_kobj;

static unsigned int defer_sync_state_count = 1;

static DEFINE_MUTEX(device_links_lock);
DEFINE_STATIC_SRCU(device_links_srcu);

static struct workqueue_struct *device_link_wq;

static inline void device_links_write_lock(void)
{
    mutex_lock(&device_links_lock);
}

static inline void device_links_write_unlock(void)
{
    mutex_unlock(&device_links_lock);
}

static ssize_t dev_attr_show(struct kobject *kobj, struct attribute *attr,
                 char *buf)
{
    PANIC("");
}

static ssize_t dev_attr_store(struct kobject *kobj, struct attribute *attr,
                  const char *buf, size_t count)
{
    PANIC("");
}

static const struct sysfs_ops dev_sysfs_ops = {
    .show   = dev_attr_show,
    .store  = dev_attr_store,
};

static const void *device_namespace(const struct kobject *kobj)
{
    PANIC("");
}

static void device_get_ownership(const struct kobject *kobj, kuid_t *uid, kgid_t *gid)
{
    PANIC("");
}

/**
 * device_release - free device structure.
 * @kobj: device's kobject.
 *
 * This is called once the reference count for the object
 * reaches 0. We forward the call to the device's release
 * method, which should handle actually freeing the structure.
 */
static void device_release(struct kobject *kobj)
{
    struct device *dev = kobj_to_dev(kobj);
    struct device_private *p = dev->p;

    /*
     * Some platform devices are driven without driver attached
     * and managed resources may have been acquired.  Make sure
     * all resources are released.
     *
     * Drivers still can add resources into device after device
     * is deleted but alive, so release devres here to avoid
     * possible memory leak.
     */
    devres_release_all(dev);

    kfree(dev->dma_range_map);

    if (dev->release)
        dev->release(dev);
    else if (dev->type && dev->type->release)
        dev->type->release(dev);
    else if (dev->class && dev->class->dev_release)
        dev->class->dev_release(dev);
    else
        WARN(1, KERN_ERR "Device '%s' does not have a release() function, it is broken and must be fixed. See Documentation/core-api/kobject.rst.\n",
            dev_name(dev));
    kfree(p);
}

static const struct kobj_type device_ktype = {
    .release    = device_release,
    .sysfs_ops  = &dev_sysfs_ops,
    .namespace  = device_namespace,
    .get_ownership  = device_get_ownership,
};

/**
 * get_device - increment reference count for device.
 * @dev: device.
 *
 * This simply forwards the call to kobject_get(), though
 * we do take care to provide for the case that we get a NULL
 * pointer passed in.
 */
struct device *get_device(struct device *dev)
{
    return dev ? kobj_to_dev(kobject_get(&dev->kobj)) : NULL;
}

/**
 * put_device - decrement reference count.
 * @dev: device in question.
 */
void put_device(struct device *dev)
{
    /* might_sleep(); */
    if (dev)
        kobject_put(&dev->kobj);
}

/**
 * device_initialize - init device structure.
 * @dev: device.
 *
 * This prepares the device for use by other layers by initializing
 * its fields.
 * It is the first half of device_register(), if called by
 * that function, though it can also be called separately, so one
 * may use @dev's fields. In particular, get_device()/put_device()
 * may be used for reference counting of @dev after calling this
 * function.
 *
 * All fields in @dev must be initialized by the caller to 0, except
 * for those explicitly set to some other value.  The simplest
 * approach is to use kzalloc() to allocate the structure containing
 * @dev.
 *
 * NOTE: Use put_device() to give up your reference instead of freeing
 * @dev directly once you have called this function.
 */
void device_initialize(struct device *dev)
{
    dev->kobj.kset = devices_kset;
    kobject_init(&dev->kobj, &device_ktype);
    INIT_LIST_HEAD(&dev->dma_pools);
    mutex_init(&dev->mutex);
    lockdep_set_novalidate_class(&dev->mutex);
    spin_lock_init(&dev->devres_lock);
    INIT_LIST_HEAD(&dev->devres_head);
    //device_pm_init(dev);
    set_dev_node(dev, NUMA_NO_NODE);
    INIT_LIST_HEAD(&dev->links.consumers);
    INIT_LIST_HEAD(&dev->links.suppliers);
    INIT_LIST_HEAD(&dev->links.defer_sync);
    dev->links.status = DL_DEV_NO_DRIVER;
#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
    dev->dma_coherent = dma_default_coherent;
#endif
    swiotlb_dev_init(dev);
}

/**
 * dev_err_probe - probe error check and log helper
 * @dev: the pointer to the struct device
 * @err: error value to test
 * @fmt: printf-style format string
 * @...: arguments as specified in the format string
 *
 * This helper implements common pattern present in probe functions for error
 * checking: print debug or error message depending if the error value is
 * -EPROBE_DEFER and propagate error upwards.
 * In case of -EPROBE_DEFER it sets also defer probe reason, which can be
 * checked later by reading devices_deferred debugfs attribute.
 * It replaces code sequence::
 *
 *  if (err != -EPROBE_DEFER)
 *      dev_err(dev, ...);
 *  else
 *      dev_dbg(dev, ...);
 *  return err;
 *
 * with::
 *
 *  return dev_err_probe(dev, err, ...);
 *
 * Using this helper in your probe function is totally fine even if @err is
 * known to never be -EPROBE_DEFER.
 * The benefit compared to a normal dev_err() is the standardized format
 * of the error code, it being emitted symbolically (i.e. you get "EAGAIN"
 * instead of "-35") and the fact that the error code is returned which allows
 * more compact error paths.
 *
 * Returns @err.
 */
int dev_err_probe(const struct device *dev, int err, const char *fmt, ...)
{
    struct va_format vaf;
    va_list args;

    va_start(args, fmt);
    vaf.fmt = fmt;
    vaf.va = &args;

    switch (err) {
    case -EPROBE_DEFER:
        device_set_deferred_probe_reason(dev, &vaf);
        dev_dbg(dev, "error %pe: %pV", ERR_PTR(err), &vaf);
        break;

    case -ENOMEM:
        /*
         * We don't print anything on -ENOMEM, there is already enough
         * output.
         */
        break;

    default:
        dev_err(dev, "error %pe: %pV", ERR_PTR(err), &vaf);
        break;
    }

    va_end(args);

    return err;
}

/**
 * dev_set_name - set a device name
 * @dev: device
 * @fmt: format string for the device's name
 */
int dev_set_name(struct device *dev, const char *fmt, ...)
{
    va_list vargs;
    int err;

    va_start(vargs, fmt);
    err = kobject_set_name_vargs(&dev->kobj, fmt, vargs);
    va_end(vargs);
    return err;
}

static void klist_children_get(struct klist_node *n)
{
    struct device_private *p = to_device_private_parent(n);
    struct device *dev = p->device;

    get_device(dev);
}

static void klist_children_put(struct klist_node *n)
{
    struct device_private *p = to_device_private_parent(n);
    struct device *dev = p->device;

    put_device(dev);
}

static int device_private_init(struct device *dev)
{
    dev->p = kzalloc(sizeof(*dev->p), GFP_KERNEL);
    if (!dev->p)
        return -ENOMEM;
    dev->p->device = dev;
    klist_init(&dev->p->klist_children, klist_children_get,
           klist_children_put);
    INIT_LIST_HEAD(&dev->p->deferred_probe);
    return 0;
}

struct class_dir {
    struct kobject kobj;
    const struct class *class;
};

#define to_class_dir(obj) container_of(obj, struct class_dir, kobj)

static void class_dir_release(struct kobject *kobj)
{
    struct class_dir *dir = to_class_dir(kobj);
    kfree(dir);
}

static const
struct kobj_ns_type_operations *class_dir_child_ns_type(const struct kobject *kobj)
{
    const struct class_dir *dir = to_class_dir(kobj);
    return dir->class->ns_type;
}

static const struct kobj_type class_dir_ktype = {
    .release    = class_dir_release,
    .sysfs_ops  = &kobj_sysfs_ops,
    .child_ns_type  = class_dir_child_ns_type
};

static struct kobject *class_dir_create_and_add(struct subsys_private *sp,
                        struct kobject *parent_kobj)
{
    struct class_dir *dir;
    int retval;

    dir = kzalloc(sizeof(*dir), GFP_KERNEL);
    if (!dir)
        return ERR_PTR(-ENOMEM);

    dir->class = sp->class;
    kobject_init(&dir->kobj, &class_dir_ktype);

    dir->kobj.kset = &sp->glue_dirs;

    retval = kobject_add(&dir->kobj, parent_kobj, "%s", sp->class->name);
    if (retval < 0) {
        kobject_put(&dir->kobj);
        return ERR_PTR(retval);
    }
    return &dir->kobj;
}

static struct kobject *get_device_parent(struct device *dev,
                     struct device *parent)
{
    struct subsys_private *sp = class_to_subsys(dev->class);
    struct kobject *kobj = NULL;

    if (sp) {
        struct kobject *parent_kobj;
        struct kobject *k;

        /*
         * If we have no parent, we live in "virtual".
         * Class-devices with a non class-device as parent, live
         * in a "glue" directory to prevent namespace collisions.
         */
        if (parent == NULL)
            parent_kobj = virtual_device_parent();
        else if (parent->class && !dev->class->ns_type) {
            subsys_put(sp);
            return &parent->kobj;
        } else {
            parent_kobj = &parent->kobj;
        }

        mutex_lock(&gdp_mutex);

        /* find our class-directory at the parent and reference it */
        spin_lock(&sp->glue_dirs.list_lock);
        list_for_each_entry(k, &sp->glue_dirs.list, entry)
            if (k->parent == parent_kobj) {
                kobj = kobject_get(k);
                break;
            }
        spin_unlock(&sp->glue_dirs.list_lock);
        if (kobj) {
            mutex_unlock(&gdp_mutex);
            subsys_put(sp);
            return kobj;
        }

        /* or create a new class-directory at the parent device */
        k = class_dir_create_and_add(sp, parent_kobj);
        /* do not emit an uevent for this simple "glue" directory */
        mutex_unlock(&gdp_mutex);
        subsys_put(sp);
        return k;
    }

    /* subsystems can specify a default root directory for their devices */
    if (!parent && dev->bus) {
        struct device *dev_root = bus_get_dev_root(dev->bus);

        if (dev_root) {
            kobj = &dev_root->kobj;
            put_device(dev_root);
            return kobj;
        }
    }

    if (parent)
        return &parent->kobj;
    return NULL;
}

/*
 * make sure cleaning up dir as the last step, we need to make
 * sure .release handler of kobject is run with holding the
 * global lock
 */
static void cleanup_glue_dir(struct device *dev, struct kobject *glue_dir)
{
    PANIC("");
}

void bus_notify(struct device *dev, enum bus_notifier_event value)
{
    struct subsys_private *sp = bus_to_subsys(dev->bus);

    if (!sp)
        return;

    blocking_notifier_call_chain(&sp->bus_notifier, value, dev);
    subsys_put(sp);
}

static void fw_devlink_relax_link(struct device_link *link)
{
    if (!(link->flags & DL_FLAG_INFERRED))
        return;

    if (device_link_flag_is_sync_state_only(link->flags))
        return;

    pm_runtime_drop_link(link);
    link->flags = DL_FLAG_MANAGED | FW_DEVLINK_FLAGS_PERMISSIVE;
    dev_dbg(link->consumer, "Relaxing link with %s\n",
        dev_name(link->supplier));
}

#define to_devlink(dev) container_of((dev), struct device_link, link_dev)

static int fw_devlink_no_driver(struct device *dev, void *data)
{
    struct device_link *link = to_devlink(dev);

    if (!link->supplier->can_match)
        fw_devlink_relax_link(link);

    return 0;
}

static void fw_devlink_parse_fwnode(struct fwnode_handle *fwnode)
{
    if (fwnode->flags & FWNODE_FLAG_LINKS_ADDED)
        return;

    fwnode_call_int_op(fwnode, add_links);
    fwnode->flags |= FWNODE_FLAG_LINKS_ADDED;
}

static void fw_devlink_parse_fwtree(struct fwnode_handle *fwnode)
{
    struct fwnode_handle *child = NULL;

    fw_devlink_parse_fwnode(fwnode);

    while ((child = fwnode_get_next_available_child_node(fwnode, child)))
        fw_devlink_parse_fwtree(child);
}

/**
 * __fw_devlink_link_to_consumers - Create device links to consumers of a device
 * @dev: Device that needs to be linked to its consumers
 *
 * This function looks at all the consumer fwnodes of @dev and creates device
 * links between the consumer device and @dev (supplier).
 *
 * If the consumer device has not been added yet, then this function creates a
 * SYNC_STATE_ONLY link between @dev (supplier) and the closest ancestor device
 * of the consumer fwnode. This is necessary to make sure @dev doesn't get a
 * sync_state() callback before the real consumer device gets to be added and
 * then probed.
 *
 * Once device links are created from the real consumer to @dev (supplier), the
 * fwnode links are deleted.
 */
static void __fw_devlink_link_to_consumers(struct device *dev)
{
    struct fwnode_handle *fwnode = dev->fwnode;
    struct fwnode_link *link, *tmp;

    list_for_each_entry_safe(link, tmp, &fwnode->consumers, s_hook) {

        PANIC("LOOP");
    }
}

/**
 * fw_devlink_create_devlink - Create a device link from a consumer to fwnode
 * @con: consumer device for the device link
 * @sup_handle: fwnode handle of supplier
 * @link: fwnode link that's being converted to a device link
 *
 * This function will try to create a device link between the consumer device
 * @con and the supplier device represented by @sup_handle.
 *
 * The supplier has to be provided as a fwnode because incorrect cycles in
 * fwnode links can sometimes cause the supplier device to never be created.
 * This function detects such cases and returns an error if it cannot create a
 * device link from the consumer to a missing supplier.
 *
 * Returns,
 * 0 on successfully creating a device link
 * -EINVAL if the device link cannot be created as expected
 * -EAGAIN if the device link cannot be created right now, but it may be
 *  possible to do that in the future
 */
static int fw_devlink_create_devlink(struct device *con,
                     struct fwnode_handle *sup_handle,
                     struct fwnode_link *link)
{
    PANIC("");
}

/**
 * __fwnode_link_del - Delete a link between two fwnode_handles.
 * @link: the fwnode_link to be deleted
 *
 * The fwnode_link_lock needs to be held when this function is called.
 */
static void __fwnode_link_del(struct fwnode_link *link)
{
    pr_debug("%pfwf Dropping the fwnode link to %pfwf\n",
         link->consumer, link->supplier);
    list_del(&link->s_hook);
    list_del(&link->c_hook);
    kfree(link);
}

/**
 * __fw_devlink_link_to_suppliers - Create device links to suppliers of a device
 * @dev: The consumer device that needs to be linked to its suppliers
 * @fwnode: Root of the fwnode tree that is used to create device links
 *
 * This function looks at all the supplier fwnodes of fwnode tree rooted at
 * @fwnode and creates device links between @dev (consumer) and all the
 * supplier devices of the entire fwnode tree at @fwnode.
 *
 * The function creates normal (non-SYNC_STATE_ONLY) device links between @dev
 * and the real suppliers of @dev. Once these device links are created, the
 * fwnode links are deleted.
 *
 * In addition, it also looks at all the suppliers of the entire fwnode tree
 * because some of the child devices of @dev that have not been added yet
 * (because @dev hasn't probed) might already have their suppliers added to
 * driver core. So, this function creates SYNC_STATE_ONLY device links between
 * @dev (consumer) and these suppliers to make sure they don't execute their
 * sync_state() callbacks before these child devices have a chance to create
 * their device links. The fwnode links that correspond to the child devices
 * aren't delete because they are needed later to create the device links
 * between the real consumer and supplier devices.
 */
static void __fw_devlink_link_to_suppliers(struct device *dev,
                       struct fwnode_handle *fwnode)
{
    bool own_link = (dev->fwnode == fwnode);
    struct fwnode_link *link, *tmp;
    struct fwnode_handle *child = NULL;

    list_for_each_entry_safe(link, tmp, &fwnode->suppliers, c_hook) {
        int ret;
        struct fwnode_handle *sup = link->supplier;

        ret = fw_devlink_create_devlink(dev, sup, link);
        if (!own_link || ret == -EAGAIN)
            continue;

        __fwnode_link_del(link);
    }

    /*
     * Make "proxy" SYNC_STATE_ONLY device links to represent the needs of
     * all the descendants. This proxy link step is needed to handle the
     * case where the supplier is added before the consumer's parent device
     * (@dev).
     */
    while ((child = fwnode_get_next_available_child_node(fwnode, child)))
        __fw_devlink_link_to_suppliers(dev, child);
}

static void fw_devlink_link_device(struct device *dev)
{
    struct fwnode_handle *fwnode = dev->fwnode;

    if (!fw_devlink_flags)
        return;

    fw_devlink_parse_fwtree(fwnode);

    guard(mutex)(&fwnode_link_lock);

    __fw_devlink_link_to_consumers(dev);
    __fw_devlink_link_to_suppliers(dev, fwnode);
}

static bool fw_devlink_is_permissive(void)
{
    return fw_devlink_flags == FW_DEVLINK_FLAGS_PERMISSIVE;
}

static void fw_devlink_unblock_consumers(struct device *dev)
{
    struct device_link *link;

    if (!fw_devlink_flags || fw_devlink_is_permissive())
        return;

    device_links_write_lock();
    list_for_each_entry(link, &dev->links.consumers, s_node)
        fw_devlink_relax_link(link);
    device_links_write_unlock();
}

/**
 * device_add - add device to device hierarchy.
 * @dev: device.
 *
 * This is part 2 of device_register(), though may be called
 * separately _iff_ device_initialize() has been called separately.
 *
 * This adds @dev to the kobject hierarchy via kobject_add(), adds it
 * to the global and sibling lists for the device, then
 * adds it to the other relevant subsystems of the driver model.
 *
 * Do not call this routine or device_register() more than once for
 * any device structure.  The driver model core is not designed to work
 * with devices that get unregistered and then spring back to life.
 * (Among other things, it's very hard to guarantee that all references
 * to the previous incarnation of @dev have been dropped.)  Allocate
 * and register a fresh new struct device instead.
 *
 * NOTE: _Never_ directly free @dev after calling this function, even
 * if it returned an error! Always use put_device() to give up your
 * reference instead.
 *
 * Rule of thumb is: if device_add() succeeds, you should call
 * device_del() when you want to get rid of it. If device_add() has
 * *not* succeeded, use *only* put_device() to drop the reference
 * count.
 */
int device_add(struct device *dev)
{
    struct subsys_private *sp;
    struct device *parent;
    struct kobject *kobj;
    struct class_interface *class_intf;
    int error = -EINVAL;
    struct kobject *glue_dir = NULL;

    dev = get_device(dev);
    if (!dev)
        goto done;

    if (!dev->p) {
        error = device_private_init(dev);
        if (error)
            goto done;
    }

    /*
     * for statically allocated devices, which should all be converted
     * some day, we need to initialize the name. We prevent reading back
     * the name, and force the use of dev_name()
     */
    if (dev->init_name) {
        error = dev_set_name(dev, "%s", dev->init_name);
        dev->init_name = NULL;
    }

    if (dev_name(dev))
        error = 0;
    /* subsystems can specify simple device enumeration */
    else if (dev->bus && dev->bus->dev_name)
        error = dev_set_name(dev, "%s%u", dev->bus->dev_name, dev->id);
    else
        error = -EINVAL;
    if (error)
        goto name_error;

    pr_debug("device: '%s': %s\n", dev_name(dev), __func__);

    parent = get_device(dev->parent);
    kobj = get_device_parent(dev, parent);
    if (IS_ERR(kobj)) {
        error = PTR_ERR(kobj);
        goto parent_error;
    }
    if (kobj)
        dev->kobj.parent = kobj;

    /* use parent numa_node */
    if (parent && (dev_to_node(dev) == NUMA_NO_NODE))
        set_dev_node(dev, dev_to_node(parent));

    /* first, register with generic layer. */
    /* we require the name to be set before, and pass NULL */
    error = kobject_add(&dev->kobj, dev->kobj.parent, NULL);
    if (error) {
        glue_dir = kobj;
        goto Error;
    }

#if 0
    /* notify platform of device entry */
    device_platform_notify(dev);

    error = device_create_file(dev, &dev_attr_uevent);
    if (error)
        goto attrError;

    error = device_add_class_symlinks(dev);
    if (error)
        goto SymlinkError;
    error = device_add_attrs(dev);
    if (error)
        goto AttrsError;
#endif
    error = bus_add_device(dev);
    if (error)
        goto BusError;
#if 0
    error = dpm_sysfs_add(dev);
    if (error)
        goto DPMError;
    device_pm_add(dev);

    if (MAJOR(dev->devt)) {
        error = device_create_file(dev, &dev_attr_dev);
        if (error)
            goto DevAttrError;

        error = device_create_sys_dev_entry(dev);
        if (error)
            goto SysEntryError;

        devtmpfs_create_node(dev);
    }
#endif

    /* Notify clients of device addition.  This call must come
     * after dpm_sysfs_add() and before kobject_uevent().
     */
    bus_notify(dev, BUS_NOTIFY_ADD_DEVICE);
    kobject_uevent(&dev->kobj, KOBJ_ADD);

    /*
     * Check if any of the other devices (consumers) have been waiting for
     * this device (supplier) to be added so that they can create a device
     * link to it.
     *
     * This needs to happen after device_pm_add() because device_link_add()
     * requires the supplier be registered before it's called.
     *
     * But this also needs to happen before bus_probe_device() to make sure
     * waiting consumers can link to it before the driver is bound to the
     * device and the driver sync_state callback is called for this device.
     */
    if (dev->fwnode && !dev->fwnode->dev) {
        dev->fwnode->dev = dev;
        fw_devlink_link_device(dev);
    }

    bus_probe_device(dev);

    /*
     * If all driver registration is done and a newly added device doesn't
     * match with any driver, don't block its consumers from probing in
     * case the consumer device is able to operate without this supplier.
     */
    if (dev->fwnode && fw_devlink_drv_reg_done && !dev->can_match)
        fw_devlink_unblock_consumers(dev);

    if (parent)
        klist_add_tail(&dev->p->knode_parent,
                   &parent->p->klist_children);

    sp = class_to_subsys(dev->class);
    if (sp) {
        mutex_lock(&sp->mutex);
        /* tie the class to the device */
        klist_add_tail(&dev->p->knode_class, &sp->klist_devices);

        /* notify any interfaces that the device is here */
        list_for_each_entry(class_intf, &sp->interfaces, node)
            if (class_intf->add_dev)
                class_intf->add_dev(dev);
        mutex_unlock(&sp->mutex);
        subsys_put(sp);
    }
done:
    put_device(dev);
    return error;
#if 0
 SysEntryError:
    if (MAJOR(dev->devt))
        device_remove_file(dev, &dev_attr_dev);
 DevAttrError:
    device_pm_remove(dev);
    dpm_sysfs_remove(dev);
 DPMError:
    device_set_driver(dev, NULL);
    bus_remove_device(dev);
#endif
 BusError:
#if 0
    device_remove_attrs(dev);
 AttrsError:
    device_remove_class_symlinks(dev);
 SymlinkError:
    device_remove_file(dev, &dev_attr_uevent);
 attrError:
    device_platform_notify_remove(dev);
    kobject_uevent(&dev->kobj, KOBJ_REMOVE);
    glue_dir = get_glue_dir(dev);
    kobject_del(&dev->kobj);
#endif
 Error:
    cleanup_glue_dir(dev, glue_dir);
parent_error:
    put_device(parent);
name_error:
    kfree(dev->p);
    dev->p = NULL;
    goto done;
}

/**
 * bus_probe_device - probe drivers for a new device
 * @dev: device to probe
 *
 * - Automatically probe for a driver if the bus allows it.
 */
void bus_probe_device(struct device *dev)
{
    struct subsys_private *sp = bus_to_subsys(dev->bus);
    struct subsys_interface *sif;

    if (!sp)
        return;

    if (sp->drivers_autoprobe)
        device_initial_probe(dev);

    mutex_lock(&sp->mutex);
    list_for_each_entry(sif, &sp->interfaces, node)
        if (sif->add_dev)
            sif->add_dev(dev, sif);
    mutex_unlock(&sp->mutex);
    subsys_put(sp);
}

/**
 * device_del - delete device from system.
 * @dev: device.
 *
 * This is the first part of the device unregistration
 * sequence. This removes the device from the lists we control
 * from here, has it removed from the other driver model
 * subsystems it was added to in device_add(), and removes it
 * from the kobject hierarchy.
 *
 * NOTE: this should be called manually _iff_ device_add() was
 * also called manually.
 */
void device_del(struct device *dev)
{
    PANIC("");
}

/**
 * device_register - register a device with the system.
 * @dev: pointer to the device structure
 *
 * This happens in two clean steps - initialize the device
 * and add it to the system. The two steps can be called
 * separately, but this is the easiest and most common.
 * I.e. you should only call the two helpers separately if
 * have a clearly defined need to use and refcount the device
 * before it is added to the hierarchy.
 *
 * For more information, see the kerneldoc for device_initialize()
 * and device_add().
 *
 * NOTE: _Never_ directly free @dev after calling this function, even
 * if it returned an error! Always use put_device() to give up the
 * reference initialized in this function instead.
 */
int device_register(struct device *dev)
{
    device_initialize(dev);
    return device_add(dev);
}

/**
 * device_create_file - create sysfs attribute file for device.
 * @dev: device.
 * @attr: device attribute descriptor.
 */
int device_create_file(struct device *dev,
               const struct device_attribute *attr)
{
    int error = 0;

    if (dev) {
#if 0
        WARN(((attr->attr.mode & S_IWUGO) && !attr->store),
            "Attribute %s: write permission without 'store'\n",
            attr->attr.name);
        WARN(((attr->attr.mode & S_IRUGO) && !attr->show),
            "Attribute %s: read permission without 'show'\n",
            attr->attr.name);
        error = sysfs_create_file(&dev->kobj, &attr->attr);
#endif
        pr_notice("%s: No impl.", __func__);
    }

    return error;
}

void device_links_supplier_sync_state_pause(void)
{
    device_links_write_lock();
    defer_sync_state_count++;
    device_links_write_unlock();
}

void device_set_node(struct device *dev, struct fwnode_handle *fwnode)
{
    dev->fwnode = fwnode;
    dev->of_node = to_of_node(fwnode);
}

/**
 * __device_links_queue_sync_state - Queue a device for sync_state() callback
 * @dev: Device to call sync_state() on
 * @list: List head to queue the @dev on
 *
 * Queues a device for a sync_state() callback when the device links write lock
 * isn't held. This allows the sync_state() execution flow to use device links
 * APIs.  The caller must ensure this function is called with
 * device_links_write_lock() held.
 *
 * This function does a get_device() to make sure the device is not freed while
 * on this list.
 *
 * So the caller must also ensure that device_links_flush_sync_list() is called
 * as soon as the caller releases device_links_write_lock().  This is necessary
 * to make sure the sync_state() is called in a timely fashion and the
 * put_device() is called on this device.
 */
static void __device_links_queue_sync_state(struct device *dev,
                        struct list_head *list)
{
    struct device_link *link;

    if (!dev_has_sync_state(dev))
        return;
    if (dev->state_synced)
        return;

    PANIC("");
}

/**
 * device_links_flush_sync_list - Call sync_state() on a list of devices
 * @list: List of devices to call sync_state() on
 * @dont_lock_dev: Device for which lock is already held by the caller
 *
 * Calls sync_state() on all the devices that have been queued for it. This
 * function is used in conjunction with __device_links_queue_sync_state(). The
 * @dont_lock_dev parameter is useful when this function is called from a
 * context where a device lock is already held.
 */
static void device_links_flush_sync_list(struct list_head *list,
                     struct device *dont_lock_dev)
{
    struct device *dev, *tmp;

    list_for_each_entry_safe(dev, tmp, list, links.defer_sync) {

        PANIC("LOOP");
    }
}

void device_links_supplier_sync_state_resume(void)
{
    struct device *dev, *tmp;
    LIST_HEAD(sync_list);

    device_links_write_lock();
    if (!defer_sync_state_count) {
        WARN(true, "Unmatched sync_state pause/resume!");
        goto out;
    }
    defer_sync_state_count--;
    if (defer_sync_state_count)
        goto out;

    list_for_each_entry_safe(dev, tmp, &deferred_sync, links.defer_sync) {
        /*
         * Delete from deferred_sync list before queuing it to
         * sync_list because defer_sync is used for both lists.
         */
        list_del_init(&dev->links.defer_sync);
        __device_links_queue_sync_state(dev, &sync_list);
    }
out:
    device_links_write_unlock();

    device_links_flush_sync_list(&sync_list, NULL);
}

static void device_create_release(struct device *dev)
{
    pr_debug("device: '%s': %s\n", dev_name(dev), __func__);
    kfree(dev);
}

static __printf(6, 0) struct device *
device_create_groups_vargs(const struct class *class, struct device *parent,
               dev_t devt, void *drvdata,
               const struct attribute_group **groups,
               const char *fmt, va_list args)
{
    struct device *dev = NULL;
    int retval = -ENODEV;

    if (IS_ERR_OR_NULL(class))
        goto error;

    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev) {
        retval = -ENOMEM;
        goto error;
    }

    device_initialize(dev);
    dev->devt = devt;
    dev->class = class;
    dev->parent = parent;
    dev->groups = groups;
    dev->release = device_create_release;
    dev_set_drvdata(dev, drvdata);

    retval = kobject_set_name_vargs(&dev->kobj, fmt, args);
    if (retval)
        goto error;

    retval = device_add(dev);
    if (retval)
        goto error;

    return dev;

error:
    put_device(dev);
    return ERR_PTR(retval);
}

/**
 * device_create - creates a device and registers it with sysfs
 * @class: pointer to the struct class that this device should be registered to
 * @parent: pointer to the parent struct device of this new device, if any
 * @devt: the dev_t for the char device to be added
 * @drvdata: the data to be added to the device for callbacks
 * @fmt: string for the device's name
 *
 * This function can be used by char device classes.  A struct device
 * will be created in sysfs, registered to the specified class.
 *
 * A "dev" file will be created, showing the dev_t for the device, if
 * the dev_t is not 0,0.
 * If a pointer to a parent struct device is passed in, the newly created
 * struct device will be a child of that device in sysfs.
 * The pointer to the struct device will be returned from the call.
 * Any further sysfs files that might be required can be created using this
 * pointer.
 *
 * Returns &struct device pointer on success, or ERR_PTR() on error.
 */
struct device *device_create(const struct class *class, struct device *parent,
                 dev_t devt, void *drvdata, const char *fmt, ...)
{
    va_list vargs;
    struct device *dev;

    va_start(vargs, fmt);
    dev = device_create_groups_vargs(class, parent, devt, drvdata, NULL,
                      fmt, vargs);
    va_end(vargs);
    return dev;
}

int device_match_of_node(struct device *dev, const void *np)
{
    return dev->of_node == np;
}

static int dev_uevent_filter(const struct kobject *kobj)
{
    PANIC("");
}

static const char *dev_uevent_name(const struct kobject *kobj)
{
    PANIC("");
}

static int dev_uevent(const struct kobject *kobj, struct kobj_uevent_env *env)
{
    PANIC("");
}

struct kobject *virtual_device_parent(void)
{
    static struct kobject *virtual_dir = NULL;

    if (!virtual_dir)
        virtual_dir = kobject_create_and_add("virtual",
                             &devices_kset->kobj);

    return virtual_dir;
}

/**
 * dev_driver_string - Return a device's driver name, if at all possible
 * @dev: struct device to get the name of
 *
 * Will return the device's driver's name if it is bound to a device.  If
 * the device is not bound to a driver, it will return the name of the bus
 * it is attached to.  If it is not attached to a bus either, an empty
 * string will be returned.
 */
const char *dev_driver_string(const struct device *dev)
{
    struct device_driver *drv;

    /* dev->driver can change to NULL underneath us because of unbinding,
     * so be careful about accessing it.  dev->bus and dev->class should
     * never change once they are set, so they don't need special care.
     */
    drv = READ_ONCE(dev->driver);
    return drv ? drv->name : dev_bus_name(dev);
}

static ssize_t status_show(struct device *dev,
               struct device_attribute *attr, char *buf)
{
    const char *output;

    switch (to_devlink(dev)->status) {
    case DL_STATE_NONE:
        output = "not tracked";
        break;
    case DL_STATE_DORMANT:
        output = "dormant";
        break;
    case DL_STATE_AVAILABLE:
        output = "available";
        break;
    case DL_STATE_CONSUMER_PROBE:
        output = "consumer probing";
        break;
    case DL_STATE_ACTIVE:
        output = "active";
        break;
    case DL_STATE_SUPPLIER_UNBIND:
        output = "supplier unbinding";
        break;
    default:
        output = "unknown";
        break;
    }

    return sysfs_emit(buf, "%s\n", output);
}
static DEVICE_ATTR_RO(status);

static ssize_t auto_remove_on_show(struct device *dev,
                   struct device_attribute *attr, char *buf)
{
    struct device_link *link = to_devlink(dev);
    const char *output;

    if (link->flags & DL_FLAG_AUTOREMOVE_SUPPLIER)
        output = "supplier unbind";
    else if (link->flags & DL_FLAG_AUTOREMOVE_CONSUMER)
        output = "consumer unbind";
    else
        output = "never";

    return sysfs_emit(buf, "%s\n", output);
}
static DEVICE_ATTR_RO(auto_remove_on);

static ssize_t runtime_pm_show(struct device *dev,
                   struct device_attribute *attr, char *buf)
{
    struct device_link *link = to_devlink(dev);

    return sysfs_emit(buf, "%d\n", !!(link->flags & DL_FLAG_PM_RUNTIME));
}
static DEVICE_ATTR_RO(runtime_pm);

static ssize_t sync_state_only_show(struct device *dev,
                    struct device_attribute *attr, char *buf)
{
    struct device_link *link = to_devlink(dev);

    return sysfs_emit(buf, "%d\n",
              !!(link->flags & DL_FLAG_SYNC_STATE_ONLY));
}
static DEVICE_ATTR_RO(sync_state_only);

static int fw_devlink_dev_sync_state(struct device *dev, void *data)
{
    PANIC("");
}

static struct attribute *devlink_attrs[] = {
    &dev_attr_status.attr,
    &dev_attr_auto_remove_on.attr,
    &dev_attr_runtime_pm.attr,
    &dev_attr_sync_state_only.attr,
    NULL,
};
ATTRIBUTE_GROUPS(devlink);

static void device_link_release_fn(struct work_struct *work)
{
    PANIC("");
}

static void devlink_dev_release(struct device *dev)
{
    struct device_link *link = to_devlink(dev);

    INIT_WORK(&link->rm_work, device_link_release_fn);
    /*
     * It may take a while to complete this work because of the SRCU
     * synchronization in device_link_release_fn() and if the consumer or
     * supplier devices get deleted when it runs, so put it into the
     * dedicated workqueue.
     */
    queue_work(device_link_wq, &link->rm_work);
}

static struct class devlink_class = {
    .name = "devlink",
    .dev_groups = devlink_groups,
    .dev_release = devlink_dev_release,
};

void fw_devlink_drivers_done(void)
{
    fw_devlink_drv_reg_done = true;
    device_links_write_lock();
    class_for_each_device(&devlink_class, NULL, NULL,
                  fw_devlink_no_driver);
    device_links_write_unlock();
}

void fw_devlink_probing_done(void)
{
    LIST_HEAD(sync_list);

    device_links_write_lock();
    class_for_each_device(&devlink_class, NULL, &sync_list,
                  fw_devlink_dev_sync_state);
    device_links_write_unlock();
    device_links_flush_sync_list(&sync_list, NULL);
}

static int device_reorder_to_tail(struct device *dev, void *not_used)
{
    struct device_link *link;

    /*
     * Devices that have not been registered yet will be put to the ends
     * of the lists during the registration, so skip them here.
     */
    if (device_is_registered(dev))
        devices_kset_move_last(dev);

    if (device_pm_initialized(dev))
        device_pm_move_last(dev);

    device_for_each_child(dev, NULL, device_reorder_to_tail);
    list_for_each_entry(link, &dev->links.consumers, s_node) {
        if (device_link_flag_is_sync_state_only(link->flags))
            continue;
        device_reorder_to_tail(link->consumer, NULL);
    }

    return 0;
}

static struct device *next_device(struct klist_iter *i)
{
    struct klist_node *n = klist_next(i);
    struct device *dev = NULL;
    struct device_private *p;

    if (n) {
        p = to_device_private_parent(n);
        dev = p->device;
    }
    return dev;
}

/**
 * device_for_each_child - device child iterator.
 * @parent: parent struct device.
 * @fn: function to be called for each device.
 * @data: data for the callback.
 *
 * Iterate over @parent's child devices, and call @fn for each,
 * passing it @data.
 *
 * We check the return of @fn each time. If it returns anything
 * other than 0, we break out and return that value.
 */
int device_for_each_child(struct device *parent, void *data,
              int (*fn)(struct device *dev, void *data))
{
    struct klist_iter i;
    struct device *child;
    int error = 0;

    if (!parent || !parent->p)
        return 0;

    klist_iter_init(&parent->p->klist_children, &i);
    while (!error && (child = next_device(&i)))
        error = fn(child, data);
    klist_iter_exit(&i);
    return error;
}

/**
 * device_pm_move_to_tail - Move set of devices to the end of device lists
 * @dev: Device to move
 *
 * This is a device_reorder_to_tail() wrapper taking the requisite locks.
 *
 * It moves the @dev along with all of its children and all of its consumers
 * to the ends of the device_kset and dpm_list, recursively.
 */
void device_pm_move_to_tail(struct device *dev)
{
    int idx;

    idx = device_links_read_lock();
    device_pm_lock();
    device_reorder_to_tail(dev, NULL);
    device_pm_unlock();
    device_links_read_unlock(idx);
}

int device_links_read_lock(void) __acquires(&device_links_srcu)
{
    return srcu_read_lock(&device_links_srcu);
}

void device_links_read_unlock(int idx) __releases(&device_links_srcu)
{
    srcu_read_unlock(&device_links_srcu, idx);
}

/**
 * devices_kset_move_last - move the device to the end of devices_kset's list.
 * @dev: device to move
 */
void devices_kset_move_last(struct device *dev)
{
    if (!devices_kset)
        return;
    pr_debug("devices_kset: Moving %s to end of list\n", dev_name(dev));
    spin_lock(&devices_kset->list_lock);
    list_move_tail(&dev->kobj.entry, &devices_kset->list);
    spin_unlock(&devices_kset->list_lock);
}

static void device_links_missing_supplier(struct device *dev)
{
    struct device_link *link;

    list_for_each_entry(link, &dev->links.suppliers, c_node) {
        if (link->status != DL_STATE_CONSUMER_PROBE)
            continue;

        if (link->supplier->links.status == DL_DEV_DRIVER_BOUND) {
            WRITE_ONCE(link->status, DL_STATE_AVAILABLE);
        } else {
            WARN_ON(!(link->flags & DL_FLAG_SYNC_STATE_ONLY));
            WRITE_ONCE(link->status, DL_STATE_DORMANT);
        }
    }
}

static bool dev_is_best_effort(struct device *dev)
{
    return (fw_devlink_best_effort && dev->can_match) ||
        (dev->fwnode && (dev->fwnode->flags & FWNODE_FLAG_BEST_EFFORT));
}

static struct fwnode_handle *fwnode_links_check_suppliers(
                        struct fwnode_handle *fwnode)
{
    struct fwnode_link *link;

    if (!fwnode || fw_devlink_is_permissive())
        return NULL;

    list_for_each_entry(link, &fwnode->suppliers, c_hook)
        if (!(link->flags &
              (FWLINK_FLAG_CYCLE | FWLINK_FLAG_IGNORE)))
            return link->supplier;

    return NULL;
}

/**
 * device_links_check_suppliers - Check presence of supplier drivers.
 * @dev: Consumer device.
 *
 * Check links from this device to any suppliers.  Walk the list of the device's
 * links to suppliers and see if all of them are available.  If not, simply
 * return -EPROBE_DEFER.
 *
 * We need to guarantee that the supplier will not go away after the check has
 * been positive here.  It only can go away in __device_release_driver() and
 * that function  checks the device's links to consumers.  This means we need to
 * mark the link as "consumer probe in progress" to make the supplier removal
 * wait for us to complete (or bad things may happen).
 *
 * Links without the DL_FLAG_MANAGED flag set are ignored.
 */
int device_links_check_suppliers(struct device *dev)
{
    struct device_link *link;
    int ret = 0, fwnode_ret = 0;
    struct fwnode_handle *sup_fw;

    /*
     * Device waiting for supplier to become available is not allowed to
     * probe.
     */
    scoped_guard(mutex, &fwnode_link_lock) {
        sup_fw = fwnode_links_check_suppliers(dev->fwnode);
        if (sup_fw) {
            if (dev_is_best_effort(dev))
                fwnode_ret = -EAGAIN;
            else
                return dev_err_probe(dev, -EPROBE_DEFER,
                             "wait for supplier %pfwf\n", sup_fw);
        }
    }

    device_links_write_lock();

    list_for_each_entry(link, &dev->links.suppliers, c_node) {
        if (!(link->flags & DL_FLAG_MANAGED))
            continue;

        if (link->status != DL_STATE_AVAILABLE &&
            !(link->flags & DL_FLAG_SYNC_STATE_ONLY)) {

            if (dev_is_best_effort(dev) &&
                link->flags & DL_FLAG_INFERRED &&
                !link->supplier->can_match) {
                ret = -EAGAIN;
                continue;
            }

            device_links_missing_supplier(dev);
            ret = dev_err_probe(dev, -EPROBE_DEFER,
                        "supplier %s not ready\n", dev_name(link->supplier));
            break;
        }
        WRITE_ONCE(link->status, DL_STATE_CONSUMER_PROBE);
    }
    dev->links.status = DL_DEV_PROBING;

    device_links_write_unlock();

    return ret ? ret : fwnode_ret;
}

static const struct kset_uevent_ops device_uevent_ops = {
    .filter =   dev_uevent_filter,
    .name =     dev_uevent_name,
    .uevent =   dev_uevent,
};

int __init devices_init(void)
{
    devices_kset = kset_create_and_add("devices", &device_uevent_ops, NULL);
    if (!devices_kset)
        return -ENOMEM;
    dev_kobj = kobject_create_and_add("dev", NULL);
    if (!dev_kobj)
        goto dev_kobj_err;
    sysfs_dev_block_kobj = kobject_create_and_add("block", dev_kobj);
    if (!sysfs_dev_block_kobj)
        goto block_kobj_err;
    sysfs_dev_char_kobj = kobject_create_and_add("char", dev_kobj);
    if (!sysfs_dev_char_kobj)
        goto char_kobj_err;
    device_link_wq = alloc_workqueue("device_link_wq", 0, 0);
    if (!device_link_wq)
        goto wq_err;

    return 0;

 wq_err:
    kobject_put(sysfs_dev_char_kobj);
 char_kobj_err:
    kobject_put(sysfs_dev_block_kobj);
 block_kobj_err:
    kobject_put(dev_kobj);
 dev_kobj_err:
    kset_unregister(devices_kset);
    return -ENOMEM;
}

static int devlink_add_symlinks(struct device *dev)
{
    PANIC("");
}

static void devlink_remove_symlinks(struct device *dev)
{
    PANIC("");
}

static struct class_interface devlink_class_intf = {
    .class = &devlink_class,
    .add_dev = devlink_add_symlinks,
    .remove_dev = devlink_remove_symlinks,
};

static int __init devlink_class_init(void)
{
    int ret;

    ret = class_register(&devlink_class);
    if (ret)
        return ret;

    ret = class_interface_register(&devlink_class_intf);
    if (ret)
        class_unregister(&devlink_class);

    return ret;
}
postcore_initcall(devlink_class_init);
