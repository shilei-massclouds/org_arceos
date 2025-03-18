#include <linux/device.h>
#include <linux/platform_device.h>

#include "booter.h"

int __platform_driver_register(struct platform_driver *drv,
                               struct module *owner)
{
    int ret;
    static char dev_name[] = "clinux_virtblk";
    struct platform_device dev;
    dev.name = dev_name;
    sbi_puts("\n__platform_driver_register ...\n");
    ret = drv->probe(&dev);
    sbi_puts("\n__platform_driver_register ok!\n");
    return 0;
}

