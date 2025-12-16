// SPDX-License-Identifier: GPL-2.0-only
/*
 * SMP initialisation and IPI support
 * Based on arch/arm64/kernel/smp.c
 *
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2015 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#include <linux/acpi.h>
#include <linux/arch_topology.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/irq.h>
#include <linux/of.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/mm.h>

#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/irq.h>
#include <asm/mmu_context.h>
#include <asm/numa.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/smp.h>
#include <uapi/asm/hwcap.h>
#include <asm/vector.h>

#include "head.h"
#include "adaptor.h"

#define acpi_parse_and_init_cpus(...)   do { } while (0)

static void __init of_parse_and_init_cpus(void)
{
    struct device_node *dn;
    unsigned long hart;
    bool found_boot_cpu = false;
    int cpuid = 1;
    int rc;

    for_each_of_cpu_node(dn) {
        rc = riscv_early_of_processor_hartid(dn, &hart);
        if (rc < 0)
            continue;

        if (hart == cpuid_to_hartid_map(0)) {
            BUG_ON(found_boot_cpu);
            found_boot_cpu = 1;
            early_map_cpu_to_node(0, of_node_to_nid(dn));
            continue;
        }
        if (cpuid >= NR_CPUS) {
            pr_warn("Invalid cpuid [%d] for hartid [%lu]\n",
                cpuid, hart);
            continue;
        }

        cpuid_to_hartid_map(cpuid) = hart;
        early_map_cpu_to_node(cpuid, of_node_to_nid(dn));
        cpuid++;
    }

    BUG_ON(!found_boot_cpu);

    if (cpuid > nr_cpu_ids)
        pr_warn("Total number of cpus [%d] is greater than nr_cpus option value [%d]\n",
            cpuid, nr_cpu_ids);
}

void __init setup_smp(void)
{
    int cpuid;

    cpu_set_ops();

    if (acpi_disabled)
        of_parse_and_init_cpus();
    else
        acpi_parse_and_init_cpus();

    for (cpuid = 1; cpuid < nr_cpu_ids; cpuid++)
        if (cpuid_to_hartid_map(cpuid) != INVALID_HARTID)
            set_cpu_possible(cpuid, true);
}

// NOTE: Remove it and use real impl!
#if 1
#include "asm/cpuidle.h"
void secondary_start_sbi()
{
    cpu_do_idle();
}
#endif

void __init smp_cpus_done(unsigned int max_cpus)
{
}
