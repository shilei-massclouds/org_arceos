#include <linux/types.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "booter.h"
#include "base.h"

void *devm_kmalloc(struct device *dev, size_t size, gfp_t gfp)
{
    printk("devm_kmalloc ..\n");
    return cl_rust_alloc(size, 8);
}

/**
 * bus_register - register a driver-core subsystem
 * @bus: bus to register
 *
 * Once we have that, we register the bus with the kobject
 * infrastructure, then register the children subsystems it has:
 * the devices and drivers that belong to the subsystem.
 */
int bus_register(struct bus_type *bus)
{
    //int retval;
    struct subsys_private *priv;
    //struct lock_class_key *key = &bus->lock_key;

    priv = kzalloc(sizeof(struct subsys_private), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;

    priv->bus = bus;
    bus->p = priv;

    //klist_init(&priv->klist_devices, klist_devices_get, klist_devices_put);
    klist_init(&priv->klist_devices, NULL, NULL);
    klist_init(&priv->klist_drivers, NULL, NULL);

    printk("bus: '%s': registered\n", bus->name);
    return 0;
}

void device_initialize(struct device *dev)
{
    printk("device_initialize %s\n", dev->init_name);
}

int ida_alloc_range(struct ida *ida, unsigned int min, unsigned int max,
            gfp_t gfp)
{
    printk("%s: %d-%d\n", __func__, min, max);
    return min;
}

int dev_set_name(struct device *dev, const char *fmt, ...)
{
    sbi_puts(fmt);
    sbi_puts("\n");
    return 0;
}

int device_add(struct device *dev)
{
    printk("%s: \n", __func__);
    return 0;
}

int bus_for_each_dev(struct bus_type *bus, struct device *start,
             void *data, int (*fn)(struct device *, void *))
{
    struct klist_iter i;
    struct device *dev;
    int error = 0;

    printk("%s: step1\n", __func__);
    if (!bus || !bus->p)
        return -EINVAL;

    printk("%s: step2\n", __func__);
    /*
    klist_iter_init_node(&bus->p->klist_devices, &i,
                 (start ? &start->p->knode_bus : NULL));
    while (!error && (dev = next_device(&i)))
        error = fn(dev, data);
    klist_iter_exit(&i);
    return error;
    */
    booter_panic("END!");
}

static int __driver_attach(struct device *dev, void *data)
{
    printk("%s: %s \n", __func__, dev->init_name);
    return 0;
}

int driver_attach(struct device_driver *drv)
{
    return bus_for_each_dev(drv->bus, NULL, drv, __driver_attach);
}

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
