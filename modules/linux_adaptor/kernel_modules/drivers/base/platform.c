#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/dma-mapping.h>
#include <linux/memblock.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/pm_runtime.h>
#include <linux/pm_domain.h>
#include <linux/idr.h>
#include <linux/acpi.h>
#include <linux/clk/clk-conf.h>
#include <linux/limits.h>
#include <linux/property.h>
#include <linux/kmemleak.h>
#include <linux/types.h>
#include <linux/iommu.h>
#include <linux/dma-map-ops.h>

#include "base.h"
//#include "power/power.h"

#include "../adaptor.h"

struct device platform_bus = {
    .init_name  = "platform",
};

struct platform_object {
    struct platform_device pdev;
    char name[];
};

/*
 * Set up default DMA mask for platform devices if the they weren't
 * previously set by the architecture / DT.
 */
static void setup_pdev_dma_masks(struct platform_device *pdev)
{
    pdev->dev.dma_parms = &pdev->dma_parms;

    if (!pdev->dev.coherent_dma_mask)
        pdev->dev.coherent_dma_mask = DMA_BIT_MASK(32);
    if (!pdev->dev.dma_mask) {
        pdev->platform_dma_mask = DMA_BIT_MASK(32);
        pdev->dev.dma_mask = &pdev->platform_dma_mask;
    }
};

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

#if 0
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
#endif

/**
 * __platform_driver_register - register a driver for platform-level devices
 * @drv: platform driver structure
 * @owner: owning module/driver
 */
int __platform_driver_register(struct platform_driver *drv,
                               struct module *owner)
{
    drv->driver.owner = owner;
    drv->driver.bus = &platform_bus_type;

    return driver_register(&drv->driver);

#if 0
    int ret;
    static struct platform_device *ppdev;

    pr_debug("%s: name(%s)\n", __func__, drv->driver.name);
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
#endif
    PANIC("");
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
#ifdef CONFIG_SPARC
    /* sparc does not have irqs represented as IORESOURCE_IRQ resources */
    if (!dev || num >= dev->archdata.num_irqs)
        goto out_not_found;
    ret = dev->archdata.irqs[num];
    goto out;
#else
    struct fwnode_handle *fwnode = dev_fwnode(&dev->dev);
    struct resource *r;

    if (is_of_node(fwnode)) {
        ret = of_irq_get(to_of_node(fwnode), num);
        if (ret > 0 || ret == -EPROBE_DEFER)
            goto out;
    }

    r = platform_get_resource(dev, IORESOURCE_IRQ, num);
    if (is_acpi_device_node(fwnode)) {
        if (r && r->flags & IORESOURCE_DISABLED) {
            ret = acpi_irq_get(ACPI_HANDLE_FWNODE(fwnode), num, r);
            if (ret)
                goto out;
        }
    }

    /*
     * The resources may pass trigger flags to the irqs that need
     * to be set up. It so happens that the trigger flags for
     * IORESOURCE_BITS correspond 1-to-1 to the IRQF_TRIGGER*
     * settings.
     */
    if (r && r->flags & IORESOURCE_BITS) {
        struct irq_data *irqd;

        irqd = irq_get_irq_data(r->start);
        if (!irqd)
            goto out_not_found;
        irqd_set_trigger_type(irqd, r->flags & IORESOURCE_BITS);
    }

    if (r) {
        ret = r->start;
        goto out;
    }

    /*
     * For the index 0 interrupt, allow falling back to GpioInt
     * resources. While a device could have both Interrupt and GpioInt
     * resources, making this fallback ambiguous, in many common cases
     * the device will only expose one IRQ, and this fallback
     * allows a common code path across either kind of resource.
     */
    if (num == 0 && is_acpi_device_node(fwnode)) {
        ret = acpi_dev_gpio_irq_get(to_acpi_device_node(fwnode), num);
        /* Our callers expect -ENXIO for missing IRQs. */
        if (ret >= 0 || ret == -EPROBE_DEFER)
            goto out;
    }

#endif
out_not_found:
    ret = -ENXIO;
out:
    if (WARN(!ret, "0 is an invalid IRQ number\n"))
        return -EINVAL;
    return ret;
}

static void platform_device_release(struct device *dev)
{
    struct platform_object *pa = container_of(dev, struct platform_object,
                          pdev.dev);

    of_node_put(pa->pdev.dev.of_node);
    kfree(pa->pdev.dev.platform_data);
    kfree(pa->pdev.mfd_cell);
    kfree(pa->pdev.resource);
    kfree(pa->pdev.driver_override);
    kfree(pa);
}

/**
 * platform_device_alloc - create a platform device
 * @name: base name of the device we're adding
 * @id: instance id
 *
 * Create a platform device object which can have other objects attached
 * to it, and which will have attached objects freed when it is released.
 */
struct platform_device *platform_device_alloc(const char *name, int id)
{
    struct platform_object *pa;

    pa = kzalloc(sizeof(*pa) + strlen(name) + 1, GFP_KERNEL);
    if (pa) {
        strcpy(pa->name, name);
        pa->pdev.name = pa->name;
        pa->pdev.id = id;
        device_initialize(&pa->pdev.dev);
        pa->pdev.dev.release = platform_device_release;
        setup_pdev_dma_masks(&pa->pdev);
    }

    return pa ? &pa->pdev : NULL;
}

/**
 * platform_device_put - destroy a platform device
 * @pdev: platform device to free
 *
 * Free all memory associated with a platform device.  This function must
 * _only_ be externally called in error cases.  All other usage is a bug.
 */
void platform_device_put(struct platform_device *pdev)
{
    if (!IS_ERR_OR_NULL(pdev))
        put_device(&pdev->dev);
}

static const struct platform_device_id *platform_match_id(
            const struct platform_device_id *id,
            struct platform_device *pdev)
{
    while (id->name[0]) {
        if (strcmp(pdev->name, id->name) == 0) {
            pdev->id_entry = id;
            return id;
        }
        id++;
    }
    return NULL;
}

static int platform_match(struct device *dev, const struct device_driver *drv)
{
    struct platform_device *pdev = to_platform_device(dev);
    struct platform_driver *pdrv = to_platform_driver(drv);

    /* When driver_override is set, only bind to the matching driver */
    if (pdev->driver_override)
        return !strcmp(pdev->driver_override, drv->name);

    /* Attempt an OF style match first */
    if (of_driver_match_device(dev, drv))
        return 1;

    /* Then try ACPI style match */
    if (acpi_driver_match_device(dev, drv))
        return 1;

    /* Then try to match against the id table */
    if (pdrv->id_table)
        return platform_match_id(pdrv->id_table, pdev) != NULL;

    /* fall-back to driver name match */
    return (strcmp(pdev->name, drv->name) == 0);
}

static int platform_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
    PANIC("");
}

static int platform_probe_fail(struct platform_device *pdev)
{
    return -ENXIO;
}

static int platform_probe(struct device *_dev)
{
    struct platform_driver *drv = to_platform_driver(_dev->driver);
    struct platform_device *dev = to_platform_device(_dev);
    int ret;

    /*
     * A driver registered using platform_driver_probe() cannot be bound
     * again later because the probe function usually lives in __init code
     * and so is gone. For these drivers .probe is set to
     * platform_probe_fail in __platform_driver_probe(). Don't even prepare
     * clocks and PM domains for these to match the traditional behaviour.
     */
    if (unlikely(drv->probe == platform_probe_fail))
        return -ENXIO;

    ret = of_clk_set_defaults(_dev->of_node, false);
    if (ret < 0)
        return ret;

    ret = dev_pm_domain_attach(_dev, true);
    if (ret)
        goto out;

    if (drv->probe) {
        ret = drv->probe(dev);
        if (ret)
            dev_pm_domain_detach(_dev, true);
    }

out:
    if (drv->prevent_deferred_probe && ret == -EPROBE_DEFER) {
        dev_warn(_dev, "probe deferral not supported\n");
        ret = -ENXIO;
    }

    return ret;
}

static void platform_remove(struct device *_dev)
{
    PANIC("");
}

static void platform_shutdown(struct device *_dev)
{
    PANIC("");
}

static int platform_dma_configure(struct device *dev)
{
    struct platform_driver *drv = to_platform_driver(dev->driver);
    struct fwnode_handle *fwnode = dev_fwnode(dev);
    enum dev_dma_attr attr;
    int ret = 0;

    if (is_of_node(fwnode)) {
        ret = of_dma_configure(dev, to_of_node(fwnode), true);
    } else if (is_acpi_device_node(fwnode)) {
#if 0
        attr = acpi_get_dma_attr(to_acpi_device_node(fwnode));
        ret = acpi_dma_configure(dev, attr);
#endif
        PANIC("No acpi.");
    }
    if (ret || drv->driver_managed_dma)
        return ret;

    ret = iommu_device_use_default_domain(dev);
    if (ret)
        arch_teardown_dma_ops(dev);

    return ret;
}

static void platform_dma_cleanup(struct device *dev)
{
    struct platform_driver *drv = to_platform_driver(dev->driver);

    if (!drv->driver_managed_dma)
        iommu_device_unuse_default_domain(dev);
}

const struct bus_type platform_bus_type = {
    .name       = "platform",
    //.dev_groups = platform_dev_groups,
    .match      = platform_match,
    .uevent     = platform_uevent,
    .probe      = platform_probe,
    .remove     = platform_remove,
    .shutdown   = platform_shutdown,
    .dma_configure  = platform_dma_configure,
    .dma_cleanup    = platform_dma_cleanup,
    //.pm     = &platform_dev_pm_ops,
};

void __weak __init early_platform_cleanup(void) { }

int __init platform_bus_init(void)
{
    int error;

    early_platform_cleanup();

    error = device_register(&platform_bus);
    if (error) {
        put_device(&platform_bus);
        return error;
    }
    error =  bus_register(&platform_bus_type);
    if (error)
        device_unregister(&platform_bus);

    return error;
}
