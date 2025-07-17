#include <linux/of.h>

#include "../adaptor.h"

/*
 * Find hart ID of the CPU DT node under which given DT node falls.
 *
 * To achieve this, we walk up the DT tree until we find an active
 * RISC-V core (HART) node and extract the cpuid from it.
 */
int riscv_of_parent_hartid(struct device_node *node, unsigned long *hartid)
{
    pr_err("%s: No impl.", __func__);
    *hartid = 0;
    return 0;
}
