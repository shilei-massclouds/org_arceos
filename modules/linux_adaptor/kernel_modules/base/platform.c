#include <linux/platform_device.h>

#include "../adaptor.h"

/**
 * __platform_driver_register - register a driver for platform-level devices
 * @drv: platform driver structure
 * @owner: owning module/driver
 */
int __platform_driver_register(struct platform_driver *drv,
                               struct module *owner)
{
    int ret;
    struct platform_device pdev;

    printk("%s: name(%s)\n", __func__, drv->driver.name);
    /*
    ret = drv->probe(&pdev);
    if (ret) {
        PANIC("bad platform dev.");
    }
    */
    PANIC("");
}
