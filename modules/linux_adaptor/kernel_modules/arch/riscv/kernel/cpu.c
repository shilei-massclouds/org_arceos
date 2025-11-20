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
