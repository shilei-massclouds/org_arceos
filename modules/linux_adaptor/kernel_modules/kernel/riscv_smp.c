#include <linux/cpu.h>
#include <linux/clockchips.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/kexec.h>
#include <linux/kgdb.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/irq_work.h>
#include <linux/nmi.h>

#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>

unsigned long __cpuid_to_hartid_map[NR_CPUS] __ro_after_init = {
    [0 ... NR_CPUS-1] = INVALID_HARTID
};

int riscv_hartid_to_cpuid(unsigned long hartid)
{
    int i;

    for (i = 0; i < NR_CPUS; i++)
        if (cpuid_to_hartid_map(i) == hartid)
            return i;

    return -ENOENT;
}

void __init smp_setup_processor_id(void)
{
    cpuid_to_hartid_map(0) = boot_cpu_hartid;
}
