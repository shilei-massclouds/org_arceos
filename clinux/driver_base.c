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
