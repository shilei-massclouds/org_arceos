#include <linux/types.h>
#include <linux/device.h>
#include "booter.h"

int register_blkdev(unsigned int major, const char *name)
{
    printk("%s: major [%d] name [%s]\n", __func__, major, name);
    return 0;
}
