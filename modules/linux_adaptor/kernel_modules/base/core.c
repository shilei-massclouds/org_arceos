#include <linux/device.h>
#include <linux/swiotlb.h>
#include <linux/dma-map-ops.h>

#include "base.h"
#include "../adaptor.h"

// Note: fullfil it.
static const struct kobj_type device_ktype;

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
    //dev->kobj.kset = devices_kset;
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

static struct kobject *get_device_parent(struct device *dev,
                     struct device *parent)
{
    pr_err("%s: No impl.", __func__);
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
    pr_err("%s: No impl.", __func__);
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
    printk("device: '%s': %s\n", dev_name(dev), __func__);

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

#if 0
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
#endif

    bus_probe_device(dev);

#if 0
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
#endif
    printk("%s: ok!\n", __func__);
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
        pr_err("%s: No impl.", __func__);
    }

    return error;
}
