#include <linux/of.h>

#include "../adaptor.h"

bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, unsigned int bit)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

bool is_acpi_device_node(const struct fwnode_handle *fwnode)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

bool is_software_node(const struct fwnode_handle *fwnode)
{
    pr_err("%s: No impl.", __func__);
    return false;
}
