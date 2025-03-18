#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>

#include "booter.h"

int __platform_driver_register(struct platform_driver *drv,
                               struct module *owner)
{
    int ret;
    static char dev_name[] = "clinux_virtblk";
    struct platform_device dev;
    struct resource r;

    r.start =   0x10008000;
    r.end   =   0x10008fff;
    r.flags =   IORESOURCE_MEM;
    r.name  =   dev_name;

    dev.name = dev_name;
    dev.num_resources = 1;
    dev.resource = &r;
    dev.platform_dma_mask = DMA_BIT_MASK(32);
    dev.dev.dma_mask = & dev.platform_dma_mask;

    sbi_puts("\n__platform_driver_register ...\n");
    ret = drv->probe(&dev);
    sbi_puts("\n__platform_driver_register ok!\n");
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

int dma_set_mask(struct device *dev, u64 mask)
{
    /*
     * Truncate the mask to the actually supported dma_addr_t width to
     * avoid generating unsupportable addresses.
     */
    mask = (dma_addr_t)mask;
    *dev->dma_mask = mask;
    return 0;
}

int dma_set_coherent_mask(struct device *dev, u64 mask)
{
    /*
     * Truncate the mask to the actually supported dma_addr_t width to
     * avoid generating unsupportable addresses.
     */
    mask = (dma_addr_t)mask;
    dev->coherent_dma_mask = mask;
    return 0;
}
