#include <linux/types.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "booter.h"
#include "base.h"

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
    struct bus_type *bus = dev->bus;
    if (bus) {
        printk("bus: '%s': add device %s\n", bus->name, dev_name(dev));
        klist_add_tail(&dev->p->knode_bus, &bus->p->klist_devices);
        printk("step2\n");
    }
    return 0;
}
