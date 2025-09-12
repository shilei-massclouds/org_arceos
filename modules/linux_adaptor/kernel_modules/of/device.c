#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/of_iommu.h>
#include <linux/of_reserved_mem.h>
#include <linux/dma-direct.h> /* for bus_dma_region */
#include <linux/dma-map-ops.h>
#include <linux/init.h>
#include <linux/mod_devicetable.h>
#include <linux/slab.h>
#include <linux/platform_device.h>

#include <asm/errno.h>
#include "of_private.h"

#include "../adaptor.h"

/**
 * of_match_device - Tell if a struct device matches an of_device_id list
 * @matches: array of of device match structures to search in
 * @dev: the of device structure to match against
 *
 * Used by a driver to check whether an platform_device present in the
 * system is in its list of supported devices.
 */
const struct of_device_id *of_match_device(const struct of_device_id *matches,
                       const struct device *dev)
{
    if (!matches || !dev->of_node || dev->of_node_reused)
        return NULL;
    return of_match_node(matches, dev->of_node);
}

/**
 * of_device_make_bus_id - Use the device node data to assign a unique name
 * @dev: pointer to device structure that is linked to a device tree node
 *
 * This routine will first try using the translated bus address to
 * derive a unique name. If it cannot, then it will prepend names from
 * parent nodes until a unique name can be derived.
 */
void of_device_make_bus_id(struct device *dev)
{
    struct device_node *node = dev->of_node;
    const __be32 *reg;
    u64 addr;
    u32 mask;

    /* Construct the name, using parent nodes if necessary to ensure uniqueness */
    while (node->parent) {
        /*
         * If the address can be translated, then that is as much
         * uniqueness as we need. Make it the first component and return
         */
        reg = of_get_property(node, "reg", NULL);
        if (reg && (addr = of_translate_address(node, reg)) != OF_BAD_ADDR) {
            if (!of_property_read_u32(node, "mask", &mask))
                dev_set_name(dev, dev_name(dev) ? "%llx.%x.%lx:%s" : "%llx.%x.%lx",
                         addr, ffs(mask) - 1, node, dev_name(dev));

            else
                dev_set_name(dev, dev_name(dev) ? "%llx.%lx:%s" : "%llx.%lx",
                         addr, node, dev_name(dev));
            return;
        }

        /* format arguments only used if dev_name() resolves to NULL */
        dev_set_name(dev, dev_name(dev) ? "%s:%s" : "%s",
                 kbasename(node->full_name), dev_name(dev));
        node = node->parent;
    }
}

static void
of_dma_set_restricted_buffer(struct device *dev, struct device_node *np)
{
    struct device_node *node, *of_node = dev->of_node;
    int count, i;

    if (!IS_ENABLED(CONFIG_DMA_RESTRICTED_POOL))
        return;

    PANIC("");
}

/**
 * of_dma_configure_id - Setup DMA configuration
 * @dev:    Device to apply DMA configuration
 * @np:     Pointer to OF node having DMA configuration
 * @force_dma:  Whether device is to be set up by of_dma_configure() even if
 *      DMA capability is not explicitly described by firmware.
 * @id:     Optional const pointer value input id
 *
 * Try to get devices's DMA configuration from DT and update it
 * accordingly.
 *
 * If platform code needs to use its own special DMA configuration, it
 * can use a platform bus notifier and handle BUS_NOTIFY_ADD_DEVICE events
 * to fix up DMA configuration.
 */
int of_dma_configure_id(struct device *dev, struct device_node *np,
            bool force_dma, const u32 *id)
{
    const struct bus_dma_region *map = NULL;
    struct device_node *bus_np;
    u64 mask, end = 0;
    bool coherent, set_map = false;
    int ret;

    if (np == dev->of_node)
        bus_np = __of_get_dma_parent(np);
    else
        bus_np = of_node_get(np);

    ret = of_dma_get_range(bus_np, &map);
    of_node_put(bus_np);
    if (ret < 0) {
        /*
         * For legacy reasons, we have to assume some devices need
         * DMA configuration regardless of whether "dma-ranges" is
         * correctly specified or not.
         */
        if (!force_dma)
            return ret == -ENODEV ? 0 : ret;
    } else {
        /* Determine the overall bounds of all DMA regions */
        end = dma_range_map_max(map);
        set_map = true;
    }

    /*
     * If @dev is expected to be DMA-capable then the bus code that created
     * it should have initialised its dma_mask pointer by this point. For
     * now, we'll continue the legacy behaviour of coercing it to the
     * coherent mask if not, but we'll no longer do so quietly.
     */
    if (!dev->dma_mask) {
        dev_warn(dev, "DMA mask not set\n");
        dev->dma_mask = &dev->coherent_dma_mask;
    }

    if (!end && dev->coherent_dma_mask)
        end = dev->coherent_dma_mask;
    else if (!end)
        end = (1ULL << 32) - 1;

    /*
     * Limit coherent and dma mask based on size and default mask
     * set by the driver.
     */
    mask = DMA_BIT_MASK(ilog2(end) + 1);
    dev->coherent_dma_mask &= mask;
    *dev->dma_mask &= mask;
    /* ...but only set bus limit and range map if we found valid dma-ranges earlier */
    if (set_map) {
        dev->bus_dma_limit = end;
        dev->dma_range_map = map;
    }

    coherent = of_dma_is_coherent(np);
    dev_dbg(dev, "device is%sdma coherent\n",
        coherent ? " " : " not ");


    ret = of_iommu_configure(dev, np, id);
    if (ret == -EPROBE_DEFER) {
        /* Don't touch range map if it wasn't set from a valid dma-ranges */
        if (set_map)
            dev->dma_range_map = NULL;
        kfree(map);
        return -EPROBE_DEFER;
    }
    /* Take all other IOMMU errors to mean we'll just carry on without it */
    dev_dbg(dev, "device is%sbehind an iommu\n",
        !ret ? " " : " not ");

    arch_setup_dma_ops(dev, coherent);

    if (ret)
        of_dma_set_restricted_buffer(dev, np);

    return 0;
}

const void *of_device_get_match_data(const struct device *dev)
{
    const struct of_device_id *match;

    match = of_match_device(dev->driver->of_match_table, dev);
    if (!match)
        return NULL;

    return match->data;
}
