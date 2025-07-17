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
    if (strcmp(drv->driver.name, "riscv-plic") != 0) {
        PANIC("NOT riscv-plic.");
    }

    memset(&node, 0, sizeof(struct device_node));
    memset(&pdev, 0, sizeof(struct platform_device));

    node.name = "plic";
    node.fwnode.ops = &of_fwnode_ops;
    pdev.dev.fwnode = &(node.fwnode);

    char compatible[] = "sifive,plic-1.0.0\0riscv,plic0";
    __add_properties(&node, "compatible", compatible, sizeof(compatible));
    unsigned int ndev = cpu_to_be32(0x5f);
    __add_properties(&node, "riscv,ndev", &ndev, sizeof(&ndev));

    ret = drv->probe(&pdev);
    if (ret) {
        PANIC("bad platform dev.");
    }
    PANIC("");
}
