// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/acpi.h>
#include <linux/cpu.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/of.h>
#include <asm/acpi.h>
#include <asm/cpufeature.h>
#include <asm/csr.h>
#include <asm/hwcap.h>
#include <asm/sbi.h>
#include <asm/smp.h>
#include <asm/pgtable.h>

/*
 * Find hart ID of the CPU DT node under which given DT node falls.
 *
 * To achieve this, we walk up the DT tree until we find an active
 * RISC-V core (HART) node and extract the cpuid from it.
 */
int riscv_of_parent_hartid(struct device_node *node, unsigned long *hartid)
{
    for (; node; node = node->parent) {
        if (of_device_is_compatible(node, "riscv")) {
            *hartid = (unsigned long)of_get_cpu_hwid(node, 0);
            if (*hartid == ~0UL) {
                pr_warn("Found CPU without hart ID\n");
                return -ENODEV;
            }
            return 0;
        }
    }

    return -1;
}

int __init riscv_early_of_processor_hartid(struct device_node *node, unsigned long *hart)
{
    const char *isa;

    if (!of_device_is_compatible(node, "riscv")) {
        pr_warn("Found incompatible CPU\n");
        return -ENODEV;
    }

    *hart = (unsigned long)of_get_cpu_hwid(node, 0);
    if (*hart == ~0UL) {
        pr_warn("Found CPU without hart ID\n");
        return -ENODEV;
    }

    if (!of_device_is_available(node)) {
        pr_info("CPU with hartid=%lu is not available\n", *hart);
        return -ENODEV;
    }

    if (of_property_read_string(node, "riscv,isa-base", &isa))
        goto old_interface;

    if (IS_ENABLED(CONFIG_32BIT) && strncasecmp(isa, "rv32i", 5)) {
        pr_warn("CPU with hartid=%lu does not support rv32i", *hart);
        return -ENODEV;
    }

    if (IS_ENABLED(CONFIG_64BIT) && strncasecmp(isa, "rv64i", 5)) {
        pr_warn("CPU with hartid=%lu does not support rv64i", *hart);
        return -ENODEV;
    }

    if (!of_property_present(node, "riscv,isa-extensions"))
        return -ENODEV;

    if (of_property_match_string(node, "riscv,isa-extensions", "i") < 0 ||
        of_property_match_string(node, "riscv,isa-extensions", "m") < 0 ||
        of_property_match_string(node, "riscv,isa-extensions", "a") < 0) {
        pr_warn("CPU with hartid=%lu does not support ima", *hart);
        return -ENODEV;
    }

    return 0;

old_interface:
    if (!riscv_isa_fallback) {
        pr_warn("CPU with hartid=%lu is invalid: this kernel does not parse \"riscv,isa\"",
            *hart);
        return -ENODEV;
    }

    if (of_property_read_string(node, "riscv,isa", &isa)) {
        pr_warn("CPU with hartid=%lu has no \"riscv,isa-base\" or \"riscv,isa\" property\n",
            *hart);
        return -ENODEV;
    }

    if (IS_ENABLED(CONFIG_32BIT) && strncasecmp(isa, "rv32ima", 7)) {
        pr_warn("CPU with hartid=%lu does not support rv32ima", *hart);
        return -ENODEV;
    }

    if (IS_ENABLED(CONFIG_64BIT) && strncasecmp(isa, "rv64ima", 7)) {
        pr_warn("CPU with hartid=%lu does not support rv64ima", *hart);
        return -ENODEV;
    }

    return 0;
}
