#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/of.h>

#include "../adaptor.h"

static void __add_properties(struct device_node *np,
                             char *key,
                             void *value,
                             size_t length)
{
    struct property *prop;

    /* Array of 4 properties for the purpose of testing */
    prop = kcalloc(1, sizeof(*prop), GFP_KERNEL);
    if (!prop) {
        PANIC("kzalloc() failed");
    }

    /* Add a new property - should pass*/
    prop->name = key;
    prop->value = value;
    prop->length = length;
    if (of_add_property(np, prop)) {
        PANIC("Adding a new property failed\n");
    }
}

static int __get_riscv_plic_device(struct device_node *pnode,
                                   struct platform_device *ppdev)
{
    memset(pnode, 0, sizeof(struct device_node));
    memset(ppdev, 0, sizeof(struct platform_device));

    pnode->name = "plic";
    pnode->fwnode.ops = &of_fwnode_ops;
    ppdev->dev.fwnode = &(pnode->fwnode);

    static char compatible[] = "sifive,plic-1.0.0\0riscv,plic0";
    __add_properties(pnode, "compatible", compatible, sizeof(compatible));
    unsigned int ndev = cpu_to_be32(0x5f);
    __add_properties(pnode, "riscv,ndev", &ndev, sizeof(&ndev));

    return 0;
}

static int __get_virtblk_device(struct device_node *pnode,
                                struct platform_device *ppdev)
{
    static struct resource r;

    memset(pnode, 0, sizeof(struct device_node));
    memset(ppdev, 0, sizeof(struct platform_device));

    r.start =   0x10008000;
    r.end   =   0x10008fff;
    r.flags =   IORESOURCE_MEM;
    r.name  =   "virtblk";

    ppdev->name = "virtblk";
    ppdev->resource = &r;
    ppdev->num_resources = 1;
    device_initialize(&ppdev->dev);

    ppdev->dev.coherent_dma_mask = DMA_BIT_MASK(32);
    ppdev->platform_dma_mask = DMA_BIT_MASK(32);
    ppdev->dev.dma_mask = &ppdev->platform_dma_mask;

    return 0;
}

/**
 * __platform_driver_register - register a driver for platform-level devices
 * @drv: platform driver structure
 * @owner: owning module/driver
 */
int __platform_driver_register(struct platform_driver *drv,
                               struct module *owner)
{
    int ret;
    struct device_node node;
    struct platform_device pdev;

    printk("%s: name(%s)\n", __func__, drv->driver.name);
    if (!drv || !drv->driver.name) {
        PANIC("Bad driver.");
    }
    if (strcmp(drv->driver.name, "riscv-plic") == 0) {
        __get_riscv_plic_device(&node, &pdev);
    } else if (strcmp(drv->driver.name, "virtio-mmio") == 0) {
        __get_virtblk_device(&node, &pdev);
    } else {
        PANIC("Bad platform device.");
    }

    ret = drv->probe(&pdev);
    if (ret) {
        PANIC("bad platform dev.");
    }
    return ret;
}

/**
 * devm_platform_get_and_ioremap_resource - call devm_ioremap_resource() for a
 *                      platform device and get resource
 *
 * @pdev: platform device to use both for memory resource lookup as well as
 *        resource management
 * @index: resource index
 * @res: optional output parameter to store a pointer to the obtained resource.
 *
 * Return: a pointer to the remapped memory or an ERR_PTR() encoded error code
 * on failure.
 */
void __iomem *
devm_platform_get_and_ioremap_resource(struct platform_device *pdev,
                unsigned int index, struct resource **res)
{
    struct resource *r;

    r = platform_get_resource(pdev, IORESOURCE_MEM, index);
    if (res)
        *res = r;
    printk("%s: ...\n", __func__);
    return devm_ioremap_resource(&pdev->dev, r);
}

/**
 * devm_platform_ioremap_resource - call devm_ioremap_resource() for a platform
 *                  device
 *
 * @pdev: platform device to use both for memory resource lookup as well as
 *        resource management
 * @index: resource index
 *
 * Return: a pointer to the remapped memory or an ERR_PTR() encoded error code
 * on failure.
 */
void __iomem *devm_platform_ioremap_resource(struct platform_device *pdev,
                         unsigned int index)
{
    return devm_platform_get_and_ioremap_resource(pdev, index, NULL);
}

/**
 * platform_get_resource - get a resource for a device
 * @dev: platform device
 * @type: resource type
 * @num: resource index
 *
 * Return: a pointer to the resource or NULL on failure.
 */
struct resource *platform_get_resource(struct platform_device *dev,
                       unsigned int type, unsigned int num)
{
    u32 i;

    printk("%s: num_resources(%u)\n", __func__, dev->num_resources);
    for (i = 0; i < dev->num_resources; i++) {
        struct resource *r = &dev->resource[i];

        if (type == resource_type(r) && num-- == 0)
            return r;
    }
    return NULL;
}
