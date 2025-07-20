#include <linux/of.h>
#include <linux/cpuhotplug.h>

#include "../adaptor.h"

#ifdef CONFIG_INIT_ALL_POSSIBLE
struct cpumask __cpu_possible_mask __ro_after_init
    = {CPU_BITS_ALL};
#else
struct cpumask __cpu_possible_mask __ro_after_init;
#endif

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

int __cpuhp_setup_state(enum cpuhp_state state,
            const char *name, bool invoke,
            int (*startup)(unsigned int cpu),
            int (*teardown)(unsigned int cpu),
            bool multi_instance)
{
    pr_err("%s: No impl.", __func__);
    if (startup) {
        startup(0);
    }
    return 0;
}
