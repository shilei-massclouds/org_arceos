#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_irq.h>

#include "../adaptor.h"

extern void cl_set_phandle_cache(phandle phandle, struct device_node *node);

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

static struct platform_device *
__get_riscv_plic_device(struct device_node *pnode,
                        struct platform_device *ppdev)
{
    memset(pnode, 0, sizeof(struct device_node));
    memset(ppdev, 0, sizeof(struct platform_device));

    pnode->name = "plic";
    pnode->phandle = 0x03;
    pnode->fwnode.ops = &of_fwnode_ops;
    ppdev->dev.fwnode = &(pnode->fwnode);

    static char compatible[] = "sifive,plic-1.0.0\0riscv,plic0";
    __add_properties(pnode, "compatible", compatible, sizeof(compatible));
    static unsigned int ndev = cpu_to_be32(0x5f);
    __add_properties(pnode, "riscv,ndev", &ndev, sizeof(ndev));

    static unsigned int reg[] = {
        cpu_to_be32(0x00),
        cpu_to_be32(0xc000000),
        cpu_to_be32(0x00),
        cpu_to_be32(0x600000)
    };
    __add_properties(pnode, "reg", reg, sizeof(reg));

    static unsigned int intr_ext[] = {
        cpu_to_be32(0x02),
        cpu_to_be32(0x0b),
        cpu_to_be32(0x02),
        cpu_to_be32(0x09),
    };
    __add_properties(pnode, "interrupts-extended", intr_ext, sizeof(intr_ext));

    static unsigned int intr_cells = cpu_to_be32(0x01);
    __add_properties(pnode, "#interrupt-cells", &intr_cells, sizeof(intr_cells));

    cl_set_phandle_cache(pnode->phandle, pnode);

    return ppdev;
}

static struct platform_device *
__get_virtblk_device(struct device_node *pnode,
                     struct platform_device *ppdev)
{
    static struct resource r;

    memset(pnode, 0, sizeof(struct device_node));
    memset(ppdev, 0, sizeof(struct platform_device));

    pnode->name = "virtblk";
    pnode->fwnode.ops = &of_fwnode_ops;
    ppdev->dev.fwnode = &(pnode->fwnode);

    static unsigned int intr_line = cpu_to_be32(0x08);
    __add_properties(pnode, "interrupts", &intr_line, sizeof(intr_line));

    static unsigned int intr_parent = cpu_to_be32(0x03);
    __add_properties(pnode, "interrupt-parent", &intr_parent, sizeof(intr_parent));

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

    return ppdev;
}

static void __init_riscv_intc_device(void)
{
    static struct device_node node;
    if (node.phandle) {
        return;
    }
    node.name = "riscv-intc";
    node.phandle = 0x02;

    static unsigned int phandle = cpu_to_be32(0x02);
    __add_properties(&node, "phandle", &phandle, sizeof(phandle));

    static unsigned int intr_cells = cpu_to_be32(0x01);
    __add_properties(&node, "#interrupt-cells", &intr_cells, sizeof(intr_cells));

    cl_set_phandle_cache(node.phandle, &node);
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
    static struct platform_device *ppdev;

    pr_err("%s: No impl.", __func__);
    printk("%s: name(%s)\n", __func__, drv->driver.name);
    if (!drv || !drv->driver.name) {
        PANIC("Bad driver.");
    }

    __init_riscv_intc_device();

    if (strcmp(drv->driver.name, "riscv-plic") == 0) {
        static struct device_node node;
        static struct platform_device pdev;
        ppdev = __get_riscv_plic_device(&node, &pdev);
    } else if (strcmp(drv->driver.name, "virtio-mmio") == 0) {
        static struct device_node node;
        static struct platform_device pdev;
        ppdev = __get_virtblk_device(&node, &pdev);
    } else {
        PANIC("Bad platform device.");
    }

    ret = drv->probe(ppdev);
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

/**
 * platform_get_irq - get an IRQ for a device
 * @dev: platform device
 * @num: IRQ number index
 *
 * Gets an IRQ for a platform device and prints an error message if finding the
 * IRQ fails. Device drivers should check the return value for errors so as to
 * not pass a negative integer value to the request_irq() APIs.
 *
 * For example::
 *
 *      int irq = platform_get_irq(pdev, 0);
 *      if (irq < 0)
 *          return irq;
 *
 * Return: non-zero IRQ number on success, negative error number on failure.
 */
int platform_get_irq(struct platform_device *dev, unsigned int num)
{
    int ret;

    ret = platform_get_irq_optional(dev, num);
    if (ret < 0)
        return dev_err_probe(&dev->dev, ret,
                     "IRQ index %u not found\n", num);

    return ret;
}

/**
 * platform_get_irq_optional - get an optional IRQ for a device
 * @dev: platform device
 * @num: IRQ number index
 *
 * Gets an IRQ for a platform device. Device drivers should check the return
 * value for errors so as to not pass a negative integer value to the
 * request_irq() APIs. This is the same as platform_get_irq(), except that it
 * does not print an error message if an IRQ can not be obtained.
 *
 * For example::
 *
 *      int irq = platform_get_irq_optional(pdev, 0);
 *      if (irq < 0)
 *          return irq;
 *
 * Return: non-zero IRQ number on success, negative error number on failure.
 */
int platform_get_irq_optional(struct platform_device *dev, unsigned int num)
{
    int ret;
    struct fwnode_handle *fwnode = dev_fwnode(&dev->dev);
    struct resource *r;

    if (is_of_node(fwnode)) {
        ret = of_irq_get(to_of_node(fwnode), num);
        if (ret > 0 || ret == -EPROBE_DEFER)
            goto out;
    }

    PANIC("");
out_not_found:
    ret = -ENXIO;
out:
    if (WARN(!ret, "0 is an invalid IRQ number\n"))
        return -EINVAL;
    return ret;
}
