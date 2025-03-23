#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/of.h>
#include <linux/irqdomain.h>
#include <linux/slab.h>
#include <linux/cpuhotplug.h>
#include <linux/irq.h>

#include "booter.h"

const struct irq_domain_ops *irq_domain_ops;

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

#define PLIC_REG_START 0xc000000
void __iomem *of_iomap(struct device_node *np, int index)
{
    void *ret;
    if (strcmp(np->name, "plic") != 0) {
        booter_panic("bad plic_node.");
    }
    ret = __va(PLIC_REG_START);
    printk("%s: (0x%lx)\n", __func__, (unsigned long)ret);
    return ret;
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

int of_irq_count(struct device_node *dev)
{
    if (strcmp(dev->name, "plic") != 0) {
        booter_panic("bad plic_node.");
    }
    return 2;
}

struct irq_domain *__irq_domain_add(struct fwnode_handle *fwnode, int size,
                    irq_hw_number_t hwirq_max, int direct_max,
                    const struct irq_domain_ops *ops,
                    void *host_data)
{
    struct irq_domain *domain;
    domain = kzalloc(sizeof(*domain) + (sizeof(unsigned int) * size),
                  GFP_KERNEL);
    if (!domain) {
        booter_panic("out of memory.");
    }
    irq_domain_ops = ops;
    return domain;
}

int of_irq_parse_one(struct device_node *device, int index,
                     struct of_phandle_args *out_irq)
{
    if (strcmp(device->name, "plic") != 0) {
        booter_panic("bad plic_node.");
    }
    out_irq->args_count = 1;
    if (index == 1) {
        out_irq->args[0] = 9;
    } else {
        out_irq->args[0] = 0xb;
    }
    return 0;
}

int riscv_of_parent_hartid(struct device_node *node)
{
    return 0;
}

struct irq_domain *irq_find_matching_fwspec(struct irq_fwspec *fwspec,
                        enum irq_domain_bus_token bus_token)
{
    return NULL;
}

int __cpuhp_setup_state(enum cpuhp_state state,
            const char *name, bool invoke,
            int (*startup)(unsigned int cpu),
            int (*teardown)(unsigned int cpu),
            bool multi_instance)
{
    startup(0);
    return 0;
}

/**
 * irq_domain_translate_onecell() - Generic translate for direct one cell
 * bindings
 */
int irq_domain_translate_onecell(struct irq_domain *d,
                 struct irq_fwspec *fwspec,
                 unsigned long *out_hwirq,
                 unsigned int *out_type)
{
    if (WARN_ON(fwspec->param_count < 1))
        return -EINVAL;
    *out_hwirq = fwspec->param[0];
    *out_type = IRQ_TYPE_NONE;
    return 0;
}

struct irq_chip *plic_chip;

void irq_domain_set_info(struct irq_domain *domain, unsigned int virq,
             irq_hw_number_t hwirq, struct irq_chip *chip,
             void *chip_data, irq_flow_handler_t handler,
             void *handler_data, const char *handler_name)
{
    plic_chip = chip;
}

void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set)
{
    printk("%s: No impl.\n", __func__);
}

struct plic_priv {
    struct cpumask lmask;
    struct irq_domain *irqdomain;
    void __iomem *regs;
};

struct irq_data *irq_get_irq_data(unsigned int irq)
{
    if (irq != 3) {
        booter_panic("bad irq!");
    }
    struct plic_priv *priv = kmalloc(sizeof(struct plic_priv), 0);
    priv->regs = __va(PLIC_REG_START);

    struct irq_data *data = kmalloc(sizeof(struct irq_data), 0);
    data->irq = 3;
    data->hwirq = 8;
    data->chip_data = priv;
    return data;
}
