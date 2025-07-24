#include <linux/device/bus.h>
#include <linux/device.h>

#include "base.h"

#include "../adaptor.h"

/* /sys/bus */
static struct kset *bus_kset;

// Note: fulfill it.
static const struct kobj_type bus_ktype = {
    /*
    .sysfs_ops  = &bus_sysfs_ops,
    .release    = bus_release,
    */
};

static const struct kobj_type driver_ktype = {
    /*
    .sysfs_ops  = &driver_sysfs_ops,
    .release    = driver_release,
    */
};

static void klist_devices_get(struct klist_node *n)
{
    struct device_private *dev_prv = to_device_private_bus(n);
    struct device *dev = dev_prv->device;

    get_device(dev);
}

static void klist_devices_put(struct klist_node *n)
{
    struct device_private *dev_prv = to_device_private_bus(n);
    struct device *dev = dev_prv->device;

    put_device(dev);
}

/**
 * bus_register - register a driver-core subsystem
 * @bus: bus to register
 *
 * Once we have that, we register the bus with the kobject
 * infrastructure, then register the children subsystems it has:
 * the devices and drivers that belong to the subsystem.
 */
int bus_register(const struct bus_type *bus)
{
    int retval;
    struct subsys_private *priv;
    struct kobject *bus_kobj;
    struct lock_class_key *key;

    priv = kzalloc(sizeof(struct subsys_private), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;

    priv->bus = bus;

    BLOCKING_INIT_NOTIFIER_HEAD(&priv->bus_notifier);

    bus_kobj = &priv->subsys.kobj;
    retval = kobject_set_name(bus_kobj, "%s", bus->name);
    if (retval)
        goto out;

    bus_kobj->kset = bus_kset;
    bus_kobj->ktype = &bus_ktype;
    priv->drivers_autoprobe = 1;

    retval = kset_register(&priv->subsys);
    if (retval)
        goto out;

#if 0
    retval = bus_create_file(bus, &bus_attr_uevent);
    if (retval)
        goto bus_uevent_fail;
#endif

    priv->devices_kset = kset_create_and_add("devices", NULL, bus_kobj);
    if (!priv->devices_kset) {
        retval = -ENOMEM;
        goto bus_devices_fail;
    }

    priv->drivers_kset = kset_create_and_add("drivers", NULL, bus_kobj);
    if (!priv->drivers_kset) {
        retval = -ENOMEM;
        goto bus_drivers_fail;
    }

    INIT_LIST_HEAD(&priv->interfaces);
    key = &priv->lock_key;
    lockdep_register_key(key);
    __mutex_init(&priv->mutex, "subsys mutex", key);
    klist_init(&priv->klist_devices, klist_devices_get, klist_devices_put);
    klist_init(&priv->klist_drivers, NULL, NULL);

    /*
    retval = add_probe_files(bus);
    if (retval)
        goto bus_probe_files_fail;

    retval = sysfs_create_groups(bus_kobj, bus->bus_groups);
    if (retval)
        goto bus_groups_fail;
        */

    pr_debug("bus: '%s': registered\n", bus->name);

    return 0;

bus_groups_fail:
    //remove_probe_files(bus);
bus_probe_files_fail:
    kset_unregister(priv->drivers_kset);
bus_drivers_fail:
    kset_unregister(priv->devices_kset);
bus_devices_fail:
    //bus_remove_file(bus, &bus_attr_uevent);
bus_uevent_fail:
    kset_unregister(&priv->subsys);
    /* Above kset_unregister() will kfree @priv */
    priv = NULL;
out:
    kfree(priv);
    return retval;
}

/**
 * bus_to_subsys - Turn a struct bus_type into a struct subsys_private
 *
 * @bus: pointer to the struct bus_type to look up
 *
 * The driver core internals needs to work on the subsys_private structure, not
 * the external struct bus_type pointer.  This function walks the list of
 * registered busses in the system and finds the matching one and returns the
 * internal struct subsys_private that relates to that bus.
 *
 * Note, the reference count of the return value is INCREMENTED if it is not
 * NULL.  A call to subsys_put() must be done when finished with the pointer in
 * order for it to be properly freed.
 */
struct subsys_private *bus_to_subsys(const struct bus_type *bus)
{
    struct subsys_private *sp = NULL;
    struct kobject *kobj;

    if (!bus || !bus_kset)
        return NULL;

    spin_lock(&bus_kset->list_lock);

    if (list_empty(&bus_kset->list))
        goto done;

    list_for_each_entry(kobj, &bus_kset->list, entry) {
        struct kset *kset = container_of(kobj, struct kset, kobj);

        sp = container_of_const(kset, struct subsys_private, subsys);
        if (sp->bus == bus)
            goto done;
    }
    sp = NULL;
done:
    sp = subsys_get(sp);
    spin_unlock(&bus_kset->list_lock);
    return sp;
}

/**
 * bus_add_device - add device to bus
 * @dev: device being added
 *
 * - Add device's bus attributes.
 * - Create links to device's bus.
 * - Add the device to its bus's list of devices.
 */
int bus_add_device(struct device *dev)
{
    struct subsys_private *sp = bus_to_subsys(dev->bus);
    int error;

    if (!sp) {
        /*
         * This is a normal operation for many devices that do not
         * have a bus assigned to them, just say that all went
         * well.
         */
        return 0;
    }

    /*
     * Reference in sp is now incremented and will be dropped when
     * the device is removed from the bus
     */

    pr_debug("bus: '%s': add device %s\n", sp->bus->name, dev_name(dev));
    printk("bus: '%s': add device %s\n", sp->bus->name, dev_name(dev));

#if 0
    error = device_add_groups(dev, sp->bus->dev_groups);
    if (error)
        goto out_put;

    error = sysfs_create_link(&sp->devices_kset->kobj, &dev->kobj, dev_name(dev));
    if (error)
        goto out_groups;

    error = sysfs_create_link(&dev->kobj, &sp->subsys.kobj, "subsystem");
    if (error)
        goto out_subsys;
#endif

    klist_add_tail(&dev->p->knode_bus, &sp->klist_devices);
    return 0;

out_subsys:
    sysfs_remove_link(&sp->devices_kset->kobj, dev_name(dev));
out_groups:
    device_remove_groups(dev, sp->bus->dev_groups);
out_put:
    subsys_put(sp);
    return error;
}

static struct device_driver *next_driver(struct klist_iter *i)
{
    struct klist_node *n = klist_next(i);
    struct driver_private *drv_priv;

    if (n) {
        drv_priv = container_of(n, struct driver_private, knode_bus);
        return drv_priv->driver;
    }
    return NULL;
}

/**
 * bus_for_each_drv - driver iterator
 * @bus: bus we're dealing with.
 * @start: driver to start iterating on.
 * @data: data to pass to the callback.
 * @fn: function to call for each driver.
 *
 * This is nearly identical to the device iterator above.
 * We iterate over each driver that belongs to @bus, and call
 * @fn for each. If @fn returns anything but 0, we break out
 * and return it. If @start is not NULL, we use it as the head
 * of the list.
 *
 * NOTE: we don't return the driver that returns a non-zero
 * value, nor do we leave the reference count incremented for that
 * driver. If the caller needs to know that info, it must set it
 * in the callback. It must also be sure to increment the refcount
 * so it doesn't disappear before returning to the caller.
 */
int bus_for_each_drv(const struct bus_type *bus, struct device_driver *start,
             void *data, int (*fn)(struct device_driver *, void *))
{
    struct subsys_private *sp = bus_to_subsys(bus);
    struct klist_iter i;
    struct device_driver *drv;
    int error = 0;

    if (!sp)
        return -EINVAL;

    klist_iter_init_node(&sp->klist_drivers, &i,
                 start ? &start->p->knode_bus : NULL);
    while ((drv = next_driver(&i)) && !error)
        error = fn(drv, data);
    klist_iter_exit(&i);
    subsys_put(sp);
    return error;
}

static struct device *next_device(struct klist_iter *i)
{
    struct klist_node *n = klist_next(i);
    struct device *dev = NULL;
    struct device_private *dev_prv;

    if (n) {
        dev_prv = to_device_private_bus(n);
        dev = dev_prv->device;
    }
    return dev;
}

/**
 * bus_for_each_dev - device iterator.
 * @bus: bus type.
 * @start: device to start iterating from.
 * @data: data for the callback.
 * @fn: function to be called for each device.
 *
 * Iterate over @bus's list of devices, and call @fn for each,
 * passing it @data. If @start is not NULL, we use that device to
 * begin iterating from.
 *
 * We check the return of @fn each time. If it returns anything
 * other than 0, we break out and return that value.
 *
 * NOTE: The device that returns a non-zero value is not retained
 * in any way, nor is its refcount incremented. If the caller needs
 * to retain this data, it should do so, and increment the reference
 * count in the supplied callback.
 */
int bus_for_each_dev(const struct bus_type *bus, struct device *start,
             void *data, int (*fn)(struct device *, void *))
{
    struct subsys_private *sp = bus_to_subsys(bus);
    struct klist_iter i;
    struct device *dev;
    int error = 0;

    if (!sp)
        return -EINVAL;

    klist_iter_init_node(&sp->klist_devices, &i,
                 (start ? &start->p->knode_bus : NULL));
    while (!error && (dev = next_device(&i)))
        error = fn(dev, data);
    klist_iter_exit(&i);
    subsys_put(sp);
    return error;
}

static int bus_uevent_filter(const struct kobject *kobj)
{
    const struct kobj_type *ktype = get_ktype(kobj);

    if (ktype == &bus_ktype)
        return 1;
    return 0;
}

/*
 * Warning, the value could go to "removed" instantly after calling this function, so be very
 * careful when calling it...
 */
bool bus_is_registered(const struct bus_type *bus)
{
    struct subsys_private *sp = bus_to_subsys(bus);
    bool is_initialized = false;

    if (sp) {
        is_initialized = true;
        subsys_put(sp);
    }
    return is_initialized;
}

/**
 * driver_find - locate driver on a bus by its name.
 * @name: name of the driver.
 * @bus: bus to scan for the driver.
 *
 * Call kset_find_obj() to iterate over list of drivers on
 * a bus to find driver by name. Return driver if found.
 *
 * This routine provides no locking to prevent the driver it returns
 * from being unregistered or unloaded while the caller is using it.
 * The caller is responsible for preventing this.
 */
struct device_driver *driver_find(const char *name, const struct bus_type *bus)
{
    struct subsys_private *sp = bus_to_subsys(bus);
    struct kobject *k;
    struct driver_private *priv;

    if (!sp)
        return NULL;

    k = kset_find_obj(sp->drivers_kset, name);
    subsys_put(sp);
    if (!k)
        return NULL;

    priv = to_driver(k);

    /* Drop reference added by kset_find_obj() */
    kobject_put(k);
    return priv->driver;
}

/**
 * bus_add_driver - Add a driver to the bus.
 * @drv: driver.
 */
int bus_add_driver(struct device_driver *drv)
{
    struct subsys_private *sp = bus_to_subsys(drv->bus);
    struct driver_private *priv;
    int error = 0;

    if (!sp)
        return -EINVAL;

    /*
     * Reference in sp is now incremented and will be dropped when
     * the driver is removed from the bus
     */
    pr_debug("bus: '%s': add driver %s\n", sp->bus->name, drv->name);
    printk("bus: '%s': add driver %s\n", sp->bus->name, drv->name);

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        error = -ENOMEM;
        goto out_put_bus;
    }
    klist_init(&priv->klist_devices, NULL, NULL);
    priv->driver = drv;
    drv->p = priv;
    priv->kobj.kset = sp->drivers_kset;
    error = kobject_init_and_add(&priv->kobj, &driver_ktype, NULL,
                     "%s", drv->name);
    if (error)
        goto out_unregister;

    klist_add_tail(&priv->knode_bus, &sp->klist_drivers);
    if (sp->drivers_autoprobe) {
        error = driver_attach(drv);
        if (error)
            goto out_del_list;
    }
#if 0
    error = module_add_driver(drv->owner, drv);
    if (error) {
        printk(KERN_ERR "%s: failed to create module links for %s\n",
            __func__, drv->name);
        goto out_detach;
    }

    error = driver_create_file(drv, &driver_attr_uevent);
    if (error) {
        printk(KERN_ERR "%s: uevent attr (%s) failed\n",
            __func__, drv->name);
    }
    error = driver_add_groups(drv, sp->bus->drv_groups);
    if (error) {
        /* How the hell do we get out of this pickle? Give up */
        printk(KERN_ERR "%s: driver_add_groups(%s) failed\n",
            __func__, drv->name);
    }

    if (!drv->suppress_bind_attrs) {
        error = add_bind_files(drv);
        if (error) {
            /* Ditto */
            printk(KERN_ERR "%s: add_bind_files(%s) failed\n",
                __func__, drv->name);
        }
    }
#endif

    return 0;

out_detach:
    driver_detach(drv);
out_del_list:
    klist_del(&priv->knode_bus);
out_unregister:
    kobject_put(&priv->kobj);
    /* drv->p is freed in driver_release()  */
    drv->p = NULL;
out_put_bus:
    subsys_put(sp);
    return error;
}

static const struct kset_uevent_ops bus_uevent_ops = {
    .filter = bus_uevent_filter,
};

int __init buses_init(void)
{
    bus_kset = kset_create_and_add("bus", &bus_uevent_ops, NULL);
    if (!bus_kset)
        return -ENOMEM;

#if 0
    system_kset = kset_create_and_add("system", NULL, &devices_kset->kobj);
    if (!system_kset) {
        /* Do error handling here as devices_init() do */
        kset_unregister(bus_kset);
        bus_kset = NULL;
        pr_err("%s: failed to create and add kset 'bus'\n", __func__);
        return -ENOMEM;
    }
#endif

    return 0;
}
