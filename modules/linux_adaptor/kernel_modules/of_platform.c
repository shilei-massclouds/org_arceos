#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/cpuhotplug.h>

#include "booter.h"

int __platform_driver_register(struct platform_driver *drv,
                               struct module *owner)
{
    int ret;
    static char dev_name[] = "clinux_virtblk";
    struct platform_device dev;
    struct resource r;

    r.start =   0xffffffc010008000;
    r.end   =   0xffffffc010008fff;
    r.flags =   IORESOURCE_MEM;
    r.name  =   dev_name;

    dev.name = dev_name;
    dev.num_resources = 1;
    dev.resource = &r;
    dev.platform_dma_mask = DMA_BIT_MASK(32);
    dev.dev.dma_mask = & dev.platform_dma_mask;

    printk("\n__platform_driver_register ...\n");
    ret = drv->probe(&dev);
    printk("\n__platform_driver_register ok!\n");
    return 0;
}

/**
 * devm_platform_ioremap_resource - call devm_ioremap_resource() for a platform
 *                  device
 *
 * @pdev: platform device to use both for memory resource lookup as well as
 *        resource management
 * @index: resource index
 */
void __iomem *devm_platform_ioremap_resource(struct platform_device *pdev,
                         unsigned int index)
{
    u32 i;

    for (i = 0; i < pdev->num_resources; i++) {
        struct resource *r = &pdev->resource[i];

        if (resource_type(r) == IORESOURCE_MEM && index-- == 0) {
            return (void *) r->start;
        }
    }
    return NULL;
}

int of_property_read_variable_u32_array(const struct device_node *np,
                   const char *propname, u32 *out_values,
                   size_t sz_min, size_t sz_max)
{
    if (strcmp(np->name, "plic") != 0) {
        booter_panic("bad plic_node.");
    }

    if (strcmp(propname, "riscv,ndev") == 0) {
        *out_values = 0x5f;
        return 1;
    }
    printk("%s: name(%s)\n", __func__, propname);
    booter_panic("bad prop.");
}

int riscv_of_parent_hartid(struct device_node *node)
{
    return 0;
}
