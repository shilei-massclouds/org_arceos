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

#ifdef ARCH_AARCH64
    r.start =   0xffff00000a003e00;
    r.end   =   0xffff00000a003fff;
#endif

#ifdef ARCH_RISCV64
    r.start =   0xffffffc010008000;
    r.end   =   0xffffffc010008fff;
#endif

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
    log_debug("%s: node %s; propname %s",
              __func__, np->name, propname);
    if (strcmp(propname, "cpu-offset") == 0) {
        return -EINVAL;
    }

    if (strcmp(np->name, "plic") != 0) {
        booter_panic("bad plic_node.");
    }

    if (strcmp(propname, "riscv,ndev") == 0) {
        *out_values = 0x5f;
        return 1;
    }
    printk("%s: name(%s)\n", __func__, propname);
    booter_panic("bad prop.");
    return 0;
}

int riscv_of_parent_hartid(struct device_node *node)
{
    return 0;
}

int __cpuhp_setup_state(enum cpuhp_state state,
            const char *name, bool invoke,
            int (*startup)(unsigned int cpu),
            int (*teardown)(unsigned int cpu),
            bool multi_instance)
{
    log_debug("%s: ...", __func__);
#ifdef ARCH_RISCV64
    startup(0);
#endif
    log_debug("%s: ok!", __func__);
    return 0;
}

/**
 * of_address_to_resource - Translate device tree address and return as resource
 *
 * Note that if your address is a PIO address, the conversion will fail if
 * the physical address can't be internally converted to an IO token with
 * pci_address_to_pio(), that is because it's either called too early or it
 * can't be matched to any host bridge IO space
 */
int of_address_to_resource(struct device_node *dev, int index,
               struct resource *r)
{
    log_debug("%s: name %s, index %d", __func__, dev->name, index);
    memset(r, 0, sizeof(struct resource));

    r->start =  0xa003e00;
    r->end =    0xa003fff;
    r->flags =  0x200;
    r->name =   "virtio_mmio@a003e00";
    return 0;
}
