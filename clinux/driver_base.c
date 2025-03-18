#include <linux/types.h>
#include <linux/device.h>
#include "booter.h"

extern void *cl_rust_alloc(unsigned long size, unsigned long align);

void *devm_kmalloc(struct device *dev, size_t size, gfp_t gfp)
{
    int i;
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
