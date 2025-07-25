#include <linux/printk.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/irq.h>
#include "booter.h"

#define PLIC_REG_START 0xc000000

extern int cl_plic_init(struct device_node *node,
                        struct device_node *parent);

struct plic_priv {
    struct cpumask lmask;
    struct irq_domain *irqdomain;
    void __iomem *regs;
};

const struct irq_domain_ops *irq_domain_ops;
struct irq_chip *plic_chip;
irq_flow_handler_t fn_plic_handle_irq;
struct device_node plic_node;
struct irq_domain root_irq_domain;
struct irq_fwspec fwspec;
struct irq_data irq_data;

void plic_handle_irq(void)
{
    log_debug("%s: ...\n", __func__);
    if (fn_plic_handle_irq == NULL) {
        booter_panic("No plic_handle_irq.");
    }
    if (plic_chip == NULL) {
        booter_panic("No plic_chip.");
    }

    struct irq_desc desc;
    desc.irq_data.chip = plic_chip;
    desc.irq_data.hwirq = 8;
    (*fn_plic_handle_irq)(&desc);
}

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

int of_irq_count(struct device_node *dev)
{
    if (strcmp(dev->name, "plic") != 0) {
        booter_panic("bad plic_node.");
    }
    return 2;
}

struct irq_data *irq_get_irq_data(unsigned int irq)
{
    if (irq == 9) {
        return NULL;
    }

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

void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set)
{
    printk("%s: No impl.\n", __func__);
}

void irq_domain_set_info(struct irq_domain *domain, unsigned int virq,
             irq_hw_number_t hwirq, struct irq_chip *chip,
             void *chip_data, irq_flow_handler_t handler,
             void *handler_data, const char *handler_name)
{
    plic_chip = chip;
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

int platform_get_irq(struct platform_device *dev, unsigned int num)
{
    int irq = 3;
    printk("---------> %s: Note impl it. num(%u) return (%d)\n",
           __func__, num, irq);
    return irq;
}

static irq_handler_t fn_vm_interrupt;
static struct virtio_mmio_device *vm_dev;

int request_threaded_irq(unsigned int irq, irq_handler_t handler,
             irq_handler_t thread_fn, unsigned long irqflags,
             const char *devname, void *dev_id)
{
    // The arg handler maybe be 'vm_interrupt'.
    printk("---------> %s: Note impl it.\n", __func__);
    printk("irq(%u) handler(%lx) thread_fn(%lx) irqflags(%lx) devname(%s) dev_id(%lx)\n",
           irq, (unsigned long)handler, (unsigned long)thread_fn, irqflags, devname, dev_id);
    if (irq != 3) {
        booter_panic("IRQ must be 3.\n");
    }
    fn_vm_interrupt = handler;
    vm_dev = dev_id;
    return 0;
}

void
__irq_set_handler(unsigned int irq,
                  irq_flow_handler_t handle,
                  int is_chained,
                  const char *name)
{
    if (irq == 9) {
        fn_plic_handle_irq = handle;
    }
}

struct irq_domain *irq_find_matching_fwspec(struct irq_fwspec *fwspec,
                        enum irq_domain_bus_token bus_token)
{
    struct irq_domain *domain = kmalloc(sizeof(struct irq_domain), 0);
    log_debug("%s: fill irq_domain\n", __func__);
    return domain;
}

unsigned int irq_of_parse_and_map(struct device_node *dev, int index)
{
    printk("%s: dev(%s) index(%d)\n", __func__, dev->name, index);
    if (strcmp(dev->name, "plic") == 0 && index == 1) {
        return 9;
    }
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

void enable_percpu_irq(unsigned int irq, unsigned int type)
{
    printk("%s: No impl. irq(%u) type(%u)\n", __func__, irq, type);
}

unsigned int irq_find_mapping(struct irq_domain *domain,
                              irq_hw_number_t hwirq)
{
    log_debug("%s: hwirq(%lu)\n", __func__, hwirq);
    if (hwirq != 8) {
        booter_panic("bad irq.");
    }
    return 3;
}

int generic_handle_irq(unsigned int irq)
{
    log_debug("%s: irq(%u)\n", __func__, irq);
    if (irq != 3) {
        booter_panic("bad irq.");
    }
    if (fn_vm_interrupt == NULL) {
        booter_panic("no vm_interrupt.");
    }
    fn_vm_interrupt(irq, vm_dev);
    return 0;
}

int cl_irq_init(void)
{
    plic_node.name = "plic";
    printk("--- plic_init ...\n\n");
    cl_plic_init(&plic_node, NULL);

    if (irq_domain_ops == NULL) {
        booter_panic("irq_domain_ops is NULL!");
    }

    fwspec.param_count = 1;
    fwspec.param[0] = 8;

    irq_domain_ops->alloc(&root_irq_domain, 1, 1, &fwspec);

    printk("--- plic_init ok!\n\n");
    return 0;
}

int cl_enable_irq(void)
{
    /* For virtio_blk, enable irq */
    irq_data.irq = 3;
    irq_data.hwirq = 8;
    plic_chip->irq_unmask(&irq_data);
    return 0;
}
