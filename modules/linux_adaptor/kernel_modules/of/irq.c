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
