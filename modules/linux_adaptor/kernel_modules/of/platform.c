#define pr_fmt(fmt) "OF: " fmt

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/amba/bus.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/sysfb.h>

#include "of_private.h"
#include "../adaptor.h"

const struct of_device_id of_default_bus_match_table[] = {
    { .compatible = "simple-bus", },
    { .compatible = "simple-mfd", },
    { .compatible = "isa", },
#ifdef CONFIG_ARM_AMBA
    { .compatible = "arm,amba-bus", },
#endif /* CONFIG_ARM_AMBA */
    {} /* Empty terminated list */
};

static const struct of_device_id of_skipped_node_table[] = {
    { .compatible = "operating-points-v2", },
    {} /* Empty terminated list */
};

static struct amba_device *of_amba_device_create(struct device_node *node,
                         const char *bus_id,
                         void *platform_data,
                         struct device *parent)
{
    return NULL;
}

static int __init of_platform_default_populate_init(void)
{
    struct device_node *node;

    device_links_supplier_sync_state_pause();

    if (IS_ENABLED(CONFIG_PPC)) {
        PANIC("CONFIG_PPC");

    } else {
#if 0
        /*
         * Handle certain compatibles explicitly, since we don't want to create
         * platform_devices for every node in /reserved-memory with a
         * "compatible",
         */
        for_each_matching_node(node, reserved_mem_matches)
            of_platform_device_create(node, NULL, NULL);

        node = of_find_node_by_path("/firmware");
        if (node) {
            of_platform_populate(node, NULL, NULL, NULL);
            of_node_put(node);
        }

        node = of_get_compatible_child(of_chosen, "simple-framebuffer");
        if (node) {
            /*
             * Since a "simple-framebuffer" device is already added
             * here, disable the Generic System Framebuffers (sysfb)
             * to prevent it from registering another device for the
             * system framebuffer later (e.g: using the screen_info
             * data that may had been filled as well).
             *
             * This can happen for example on DT systems that do EFI
             * booting and may provide a GOP handle to the EFI stub.
             */
            sysfb_disable(NULL);
            of_platform_device_create(node, NULL, NULL);
            of_node_put(node);
        }
#endif

        /* Populate everything else. */
        of_platform_default_populate(NULL, NULL, NULL);
    }

    return 0;
}

int of_platform_default_populate(struct device_node *root,
                 const struct of_dev_auxdata *lookup,
                 struct device *parent)
{
    return of_platform_populate(root, of_default_bus_match_table, lookup,
                    parent);
}

/*
 * of_dev_lookup() - Given a device node, lookup the preferred Linux name
 */
static const struct of_dev_auxdata *of_dev_lookup(const struct of_dev_auxdata *lookup,
                 struct device_node *np)
{
    const struct of_dev_auxdata *auxdata;
    struct resource res;
    int compatible = 0;

    if (!lookup)
        return NULL;

    PANIC("");
}

/*
 * The following routines scan a subtree and registers a device for
 * each applicable node.
 *
 * Note: sparc doesn't use these routines because it has a different
 * mechanism for creating devices from device tree nodes.
 */

/**
 * of_device_alloc - Allocate and initialize an of_device
 * @np: device node to assign to device
 * @bus_id: Name to assign to the device.  May be null to use default name.
 * @parent: Parent device.
 */
struct platform_device *of_device_alloc(struct device_node *np,
                  const char *bus_id,
                  struct device *parent)
{
    struct platform_device *dev;
    int rc, i, num_reg = 0;
    struct resource *res;

    dev = platform_device_alloc("", PLATFORM_DEVID_NONE);
    if (!dev)
        return NULL;

    /* count the io resources */
    num_reg = of_address_count(np);

    printk("%s: num_reg(%u)\n", __func__, num_reg);
    /* Populate the resource table */
    if (num_reg) {
        res = kcalloc(num_reg, sizeof(*res), GFP_KERNEL);
        if (!res) {
            platform_device_put(dev);
            return NULL;
        }

        dev->num_resources = num_reg;
        dev->resource = res;
        for (i = 0; i < num_reg; i++, res++) {
            rc = of_address_to_resource(np, i, res);
            WARN_ON(rc);
        }
    }

    /* setup generic device info */
    device_set_node(&dev->dev, of_fwnode_handle(of_node_get(np)));
    dev->dev.parent = parent ? : &platform_bus;

    if (bus_id)
        dev_set_name(&dev->dev, "%s", bus_id);
    else
        of_device_make_bus_id(&dev->dev);

    printk("%s: ok!\n", __func__);
    return dev;
}

int of_device_add(struct platform_device *ofdev)
{
    BUG_ON(ofdev->dev.of_node == NULL);

    /* name and id have to be set so that the platform bus doesn't get
     * confused on matching */
    ofdev->name = dev_name(&ofdev->dev);
    ofdev->id = PLATFORM_DEVID_NONE;

    /*
     * If this device has not binding numa node in devicetree, that is
     * of_node_to_nid returns NUMA_NO_NODE. device_add will assume that this
     * device is on the same node as the parent.
     */
    set_dev_node(&ofdev->dev, of_node_to_nid(ofdev->dev.of_node));

    return device_add(&ofdev->dev);
}

/**
 * of_platform_device_create_pdata - Alloc, initialize and register an of_device
 * @np: pointer to node to create device for
 * @bus_id: name to assign device
 * @platform_data: pointer to populate platform_data pointer with
 * @parent: Linux device model parent device.
 *
 * Return: Pointer to created platform device, or NULL if a device was not
 * registered.  Unavailable devices will not get registered.
 */
static struct platform_device *of_platform_device_create_pdata(
                    struct device_node *np,
                    const char *bus_id,
                    void *platform_data,
                    struct device *parent)
{
    struct platform_device *dev;

    pr_debug("create platform device: %pOF\n", np);

    if (!of_device_is_available(np) ||
        of_node_test_and_set_flag(np, OF_POPULATED))
        return NULL;

    dev = of_device_alloc(np, bus_id, parent);
    if (!dev)
        goto err_clear_flag;

    dev->dev.coherent_dma_mask = DMA_BIT_MASK(32);
    if (!dev->dev.dma_mask)
        dev->dev.dma_mask = &dev->dev.coherent_dma_mask;
    dev->dev.bus = &platform_bus_type;
    dev->dev.platform_data = platform_data;
    of_msi_configure(&dev->dev, dev->dev.of_node);

    if (of_device_add(dev) != 0) {
        platform_device_put(dev);
        goto err_clear_flag;
    }

    return dev;

err_clear_flag:
    of_node_clear_flag(np, OF_POPULATED);
    return NULL;
}

/**
 * of_platform_bus_create() - Create a device for a node and its children.
 * @bus: device node of the bus to instantiate
 * @matches: match table for bus nodes
 * @lookup: auxdata table for matching id and platform_data with device nodes
 * @parent: parent for new device, or NULL for top level.
 * @strict: require compatible property
 *
 * Creates a platform_device for the provided device_node, and optionally
 * recursively create devices for all the child nodes.
 */
static int of_platform_bus_create(struct device_node *bus,
                  const struct of_device_id *matches,
                  const struct of_dev_auxdata *lookup,
                  struct device *parent, bool strict)
{
    const struct of_dev_auxdata *auxdata;
    struct platform_device *dev;
    const char *bus_id = NULL;
    void *platform_data = NULL;
    int rc = 0;

    /* Make sure it has a compatible property */
    if (strict && (!of_get_property(bus, "compatible", NULL))) {
        pr_debug("%s() - skipping %pOF, no compatible prop\n",
             __func__, bus);
        return 0;
    }

    /* Skip nodes for which we don't want to create devices */
    if (unlikely(of_match_node(of_skipped_node_table, bus))) {
        pr_debug("%s() - skipping %pOF node\n", __func__, bus);
        return 0;
    }

    if (of_node_check_flag(bus, OF_POPULATED_BUS)) {
        pr_debug("%s() - skipping %pOF, already populated\n",
            __func__, bus);
        return 0;
    }

    auxdata = of_dev_lookup(lookup, bus);
    if (auxdata) {
        bus_id = auxdata->name;
        platform_data = auxdata->platform_data;
    }

    if (of_device_is_compatible(bus, "arm,primecell")) {
        /*
         * Don't return an error here to keep compatibility with older
         * device tree files.
         */
        of_amba_device_create(bus, bus_id, platform_data, parent);
        return 0;
    }

    dev = of_platform_device_create_pdata(bus, bus_id, platform_data, parent);
    if (!dev || !of_match_node(matches, bus))
        return 0;

    for_each_child_of_node_scoped(bus, child) {
        pr_debug("   create child: %pOF\n", child);
        printk("   create child: %lx\n", child);
        rc = of_platform_bus_create(child, matches, lookup, &dev->dev, strict);
        if (rc)
            break;
    }
    of_node_set_flag(bus, OF_POPULATED_BUS);
    return rc;
}

/**
 * of_platform_populate() - Populate platform_devices from device tree data
 * @root: parent of the first level to probe or NULL for the root of the tree
 * @matches: match table, NULL to use the default
 * @lookup: auxdata table for matching id and platform_data with device nodes
 * @parent: parent to hook devices from, NULL for toplevel
 *
 * Similar to of_platform_bus_probe(), this function walks the device tree
 * and creates devices from nodes.  It differs in that it follows the modern
 * convention of requiring all device nodes to have a 'compatible' property,
 * and it is suitable for creating devices which are children of the root
 * node (of_platform_bus_probe will only create children of the root which
 * are selected by the @matches argument).
 *
 * New board support should be using this function instead of
 * of_platform_bus_probe().
 *
 * Return: 0 on success, < 0 on failure.
 */
int of_platform_populate(struct device_node *root,
            const struct of_device_id *matches,
            const struct of_dev_auxdata *lookup,
            struct device *parent)
{
    int rc = 0;

    root = root ? of_node_get(root) : of_find_node_by_path("/");
    if (!root)
        return -EINVAL;

    pr_debug("%s()\n", __func__);
    pr_debug(" starting at: %pOF\n", root);

    device_links_supplier_sync_state_pause();
    for_each_child_of_node_scoped(root, child) {
        rc = of_platform_bus_create(child, matches, lookup, parent, true);
        if (rc)
            break;
    }
    device_links_supplier_sync_state_resume();

    of_node_set_flag(root, OF_POPULATED_BUS);

    of_node_put(root);
    return rc;
}

int __init cl_of_platform_default_populate_init(void)
{
    return of_platform_default_populate_init();
}
