#include <linux/types.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "booter.h"
#include "base.h"

void device_initialize(struct device *dev)
{
    printk("device_initialize %s\n", dev->init_name);
}

int dev_set_name(struct device *dev, const char *fmt, ...)
{
    printk("%s: fmt %s\n", __func__, fmt);
    return 0;
}

static int device_private_init(struct device *dev)
{
    dev->p = kzalloc(sizeof(*dev->p), GFP_KERNEL);
    if (!dev->p)
        return -ENOMEM;
    dev->p->device = dev;
    //klist_init(&dev->p->klist_children, klist_children_get, klist_children_put);
    klist_init(&dev->p->klist_children, NULL, NULL);
    INIT_LIST_HEAD(&dev->p->deferred_probe);
    return 0;
}

int device_add(struct device *dev)
{
    int error;
    printk("%s: \n", __func__);

    if (!dev->p) {
        error = device_private_init(dev);
        if (error) {
            booter_panic("device_private_init error!");
        }
    }

    error = bus_add_device(dev);
    if (error) {
        booter_panic("device_add error!");
    }

    return 0;
}
