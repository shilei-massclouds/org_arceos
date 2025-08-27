#include <linux/smp.h>

#if (NR_CPUS > 1) && !defined(CONFIG_FORCE_NR_CPUS)
/* Setup number of possible processor ids */
unsigned int nr_cpu_ids __read_mostly = NR_CPUS;
EXPORT_SYMBOL(nr_cpu_ids);
#endif

int riscv_hartid_to_cpuid(unsigned long hartid)
{
    pr_notice("%s: No impl. hartid(%lu)", __func__, hartid);
    return 0;
}
