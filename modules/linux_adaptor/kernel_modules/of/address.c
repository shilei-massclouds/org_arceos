#include <linux/of_address.h>

#include "../adaptor.h"

static int __of_address_to_resource(struct device_node *dev, int index, int bar_no,
        struct resource *r)
{
    pr_notice("%s: No impl.", __func__);

    if (dev && dev->name && !strcmp(dev->name, "plic")) {
        r->start = 0xc000000;
        r->end = 0xc5fffff;
        r->flags = IORESOURCE_MEM;
        return 0;
    }
    PANIC("Bad device_node.");
}

/**
 * of_address_to_resource - Translate device tree address and return as resource
 * @dev:    Caller's Device Node
 * @index:  Index into the array
 * @r:      Pointer to resource array
 *
 * Returns -EINVAL if the range cannot be converted to resource.
 *
 * Note that if your address is a PIO address, the conversion will fail if
 * the physical address can't be internally converted to an IO token with
 * pci_address_to_pio(), that is because it's either called too early or it
 * can't be matched to any host bridge IO space
 */
int of_address_to_resource(struct device_node *dev, int index,
               struct resource *r)
{
    return __of_address_to_resource(dev, index, -1, r);
}

/**
 * of_iomap - Maps the memory mapped IO for a given device_node
 * @np:     the device whose io range will be mapped
 * @index:  index of the io range
 *
 * Returns a pointer to the mapped memory
 */
void __iomem *of_iomap(struct device_node *np, int index)
{
    void *ret;
    struct resource res;

    if (of_address_to_resource(np, index, &res))
        return NULL;

    pr_debug("%s: (%s) res [%lx,%lx](%lx)\n", __func__, np->name, res.start, res.end, res.flags);

    ret = __va(res.start);
    return ret;
}
