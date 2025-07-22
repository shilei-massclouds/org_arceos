#include <linux/irq.h>
#include <linux/of.h>
#include <linux/of_irq.h>

#include "../adaptor.h"

int of_irq_count(struct device_node *dev)
{
    struct of_phandle_args irq;
    int nr = 0;

    printk("%s: ..\n", __func__);

    while (of_irq_parse_one(dev, nr, &irq) == 0) {
        of_node_put(irq.np);
        nr++;
    }

    printk("%s: irq_count(%u)\n", __func__, nr);
    return nr;
}

/**
 * of_irq_find_parent - Given a device node, find its interrupt parent node
 * @child: pointer to device node
 *
 * Return: A pointer to the interrupt parent node, or NULL if the interrupt
 * parent could not be determined.
 */
struct device_node *of_irq_find_parent(struct device_node *child)
{
    struct device_node *p;
    phandle parent;

    if (!of_node_get(child))
        return NULL;

    do {
        if (of_property_read_u32(child, "interrupt-parent", &parent)) {
            p = of_get_parent(child);
        } else  {
            printk("%s: parent(%u)\n", __func__, parent);
            if (of_irq_workarounds & OF_IMAP_NO_PHANDLE)
                p = of_node_get(of_irq_dflt_pic);
            else
                p = of_find_node_by_phandle(parent);
        }
        of_node_put(child);
        child = p;
    } while (p && of_get_property(p, "#interrupt-cells", NULL) == NULL);

    return p;
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
    struct device_node __free(device_node) *p = NULL;
    const __be32 *addr;
    u32 intsize;
    int i, res, addr_len;
    __be32 addr_buf[3] = { 0 };

    pr_debug("of_irq_parse_one: dev=%pOF, index=%d\n", device, index);
    printk("of_irq_parse_one: dev=%s, index=%d\n", device->name, index);

    /* OldWorld mac stuff is "special", handle out of line */
    if (of_irq_workarounds & OF_IMAP_OLDWORLD_MAC)
        return of_irq_parse_oldworld(device, index, out_irq);

    /* Get the reg property (if any) */
    addr_len = 0;
    addr = of_get_property(device, "reg", &addr_len);

    /* Prevent out-of-bounds read in case of longer interrupt parent address size */
    if (addr_len > sizeof(addr_buf))
        addr_len = sizeof(addr_buf);
    if (addr)
        memcpy(addr_buf, addr, addr_len);

    /* Try the new-style interrupts-extended first */
    res = of_parse_phandle_with_args(device, "interrupts-extended",
                    "#interrupt-cells", index, out_irq);
    if (!res) {
        printk("%s: ok dev(%s)\n", __func__, device->name);
        p = out_irq->np;
    } else {
        /* Look for the interrupt parent. */
        printk("%s: ... dev(%s)\n", __func__, device->name);
        p = of_irq_find_parent(device);
        /* Get size of interrupt specifier */
        if (!p || of_property_read_u32(p, "#interrupt-cells", &intsize))
            return -EINVAL;

        pr_debug(" parent=%pOF, intsize=%d\n", p, intsize);
        printk(" parent=%pOF, intsize=%d\n", p, intsize);

        /* Copy intspec into irq structure */
        out_irq->np = p;
        out_irq->args_count = intsize;
        for (i = 0; i < intsize; i++) {
            res = of_property_read_u32_index(device, "interrupts",
                            (index * intsize) + i,
                            out_irq->args + i);
            if (res)
                return res;
        }

        pr_debug(" intspec=%d\n", *out_irq->args);
        printk(" intspec=%d\n", *out_irq->args);
    }

    /* Check if there are any interrupt-map translations to process */
    return of_irq_parse_raw(addr_buf, out_irq);
}

/**
 * of_irq_parse_raw - Low level interrupt tree parsing
 * @addr:   address specifier (start of "reg" property of the device) in be32 format
 * @out_irq:    structure of_phandle_args updated by this function
 *
 * This function is a low-level interrupt tree walking function. It
 * can be used to do a partial walk with synthetized reg and interrupts
 * properties, for example when resolving PCI interrupts when no device
 * node exist for the parent. It takes an interrupt specifier structure as
 * input, walks the tree looking for any interrupt-map properties, translates
 * the specifier for each map, and then returns the translated map.
 *
 * Return: 0 on success and a negative number on error
 *
 * Note: refcount of node @out_irq->np is increased by 1 on success.
 */
int of_irq_parse_raw(const __be32 *addr, struct of_phandle_args *out_irq)
{
    pr_err("%s: No impl. args_count(%u) args(%u)",
           __func__, out_irq->args_count, out_irq->args[0]);
    return 0;
}

/**
 * of_irq_get - Decode a node's IRQ and return it as a Linux IRQ number
 * @dev: pointer to device tree node
 * @index: zero-based index of the IRQ
 *
 * Return: Linux IRQ number on success, or 0 on the IRQ mapping failure, or
 * -EPROBE_DEFER if the IRQ domain is not yet created, or error code in case
 * of any other failure.
 */
int of_irq_get(struct device_node *dev, int index)
{
    int rc;
    struct of_phandle_args oirq;
    struct irq_domain *domain;

    rc = of_irq_parse_one(dev, index, &oirq);
    if (rc)
        return rc;

    domain = irq_find_host(oirq.np);
    if (!domain) {
        rc = -EPROBE_DEFER;
        goto out;
    }

    rc = irq_create_of_mapping(&oirq);
out:
    of_node_put(oirq.np);

    PANIC("");
    return rc;
}
