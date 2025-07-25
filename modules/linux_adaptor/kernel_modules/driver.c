#include <linux/types.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "booter.h"
#include "base.h"

int driver_register(struct device_driver *drv)
{
    int error;
    printk("%s: drv [%s] bus [%s]\n", __func__, drv->name, drv->bus->name);
    error = driver_attach(drv);
    if (error) {
        booter_panic("driver attaches device error!");
    }
    return 0;
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

int bus_for_each_dev(struct bus_type *bus, struct device *start,
             void *data, int (*fn)(struct device *, void *))
{
    struct klist_iter i;
    struct device *dev;
    int error = 0;

    if (!bus || !bus->p)
        return -EINVAL;

    klist_iter_init_node(&bus->p->klist_devices, &i,
                 (start ? &start->p->knode_bus : NULL));
    while (!error && (dev = next_device(&i)))
        error = fn(dev, data);

    klist_iter_exit(&i);
    return error;
}

/**
 * driver_probe_device - attempt to bind device & driver together
 * @drv: driver to bind a device to
 * @dev: device to try to bind to the driver
 *
 * This function returns -ENODEV if the device is not registered,
 * 1 if the device is bound successfully and 0 otherwise.
 *
 * This function must be called with @dev lock held.  When called for a
 * USB interface, @dev->parent lock must be held as well.
 *
 * If the device has a parent, runtime-resume the parent before driver probing.
 */
int driver_probe_device(struct device_driver *drv, struct device *dev)
{
    int ret;

    printk("bus: '%s': %s: matched device %s with driver %s\n",
         drv->bus->name, __func__, dev_name(dev), drv->name);

    dev->driver = drv;

    if (dev->bus->probe) {
        ret = dev->bus->probe(dev);
        if (ret) {
            booter_panic("bus probe error!");
        }
    } else if (drv->probe) {
        ret = drv->probe(dev);
        if (ret) {
            booter_panic("drv probe error!");
        }
    }

    return 0;
}

/**
 * device_driver_attach - attach a specific driver to a specific device
 * @drv: Driver to attach
 * @dev: Device to attach it to
 *
 * Manually attach driver to a device. Will acquire both @dev lock and
 * @dev->parent lock if needed.
 */
int device_driver_attach(struct device_driver *drv, struct device *dev)
{
    int ret = 0;

    //__device_driver_lock(dev, dev->parent);

    /*
     * If device has been removed or someone has already successfully
     * bound a driver before us just skip the driver probe call.
     */
    if (!dev->p->dead && !dev->driver)
        ret = driver_probe_device(drv, dev);

    //__device_driver_unlock(dev, dev->parent);

    return ret;
}

static int __driver_attach(struct device *dev, void *data)
{
    int ret;
    struct device_driver *drv = data;

    printk("%s: (%s) : (%s)\n", __func__, dev->init_name, drv->name);

    ret = driver_match_device(drv, dev);
    if (ret == 0) {
        /* no match */
        return 0;
    } else if (ret == -EPROBE_DEFER) {
        printk("Device match requests probe deferral\n");
        //driver_deferred_probe_add(dev);
    } else if (ret < 0) {
        printk("Bus failed to match device: %d\n", ret);
        return ret;
    } /* ret > 0 means positive match */

    printk("%s: matched! (%s) : (%s)\n", __func__, dev->init_name, drv->name);
    device_driver_attach(drv, dev);
    return 0;
}

int driver_attach(struct device_driver *drv)
{
    return bus_for_each_dev(drv->bus, NULL, drv, __driver_attach);
}
