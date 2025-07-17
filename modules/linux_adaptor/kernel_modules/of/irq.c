#include <linux/irq.h>
#include <linux/of.h>

#include "../adaptor.h"

int of_irq_count(struct device_node *dev)
{
    pr_err("%s: No impl.", __func__);
    if (strcmp(dev->name, "plic") != 0) {
        PANIC("bad plic_node.");
    }
    return 2;
}

/**
 * of_irq_parse_one - Resolve an interrupt for a device
 * @device: the device whose interrupt is to be resolved
 * @index: index of the interrupt to resolve
 * @out_irq: structure of_phandle_args filled by this function
 *
 * This function resolves an interrupt for a node by walking the interrupt tree,
 * finding which interrupt controller node it is attached to, and returning the
 * interrupt specifier that can be used to retrieve a Linux IRQ number.
 *
 * Note: refcount of node @out_irq->np is increased by 1 on success.
 */
int of_irq_parse_one(struct device_node *device, int index, struct of_phandle_args *out_irq)
{
    pr_err("%s: No impl.", __func__);
    if (strcmp(device->name, "plic") != 0) {
        PANIC("bad plic_node.");
    }
    out_irq->args_count = 1;
    if (index == 1) {
        out_irq->args[0] = 9;
    } else {
        out_irq->args[0] = 0xb;
    }
    return 0;
}
