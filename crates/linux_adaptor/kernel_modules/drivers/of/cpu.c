// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/of.h>

/**
 * of_get_cpu_hwid - Get the hardware ID from a CPU device node
 *
 * @cpun: CPU number(logical index) for which device node is required
 * @thread: The local thread number to get the hardware ID for.
 *
 * Return: The hardware ID for the CPU node or ~0ULL if not found.
 */
u64 of_get_cpu_hwid(struct device_node *cpun, unsigned int thread)
{
    const __be32 *cell;
    int ac, len;

    ac = of_n_addr_cells(cpun);
    cell = of_get_property(cpun, "reg", &len);
    if (!cell || !ac || ((sizeof(*cell) * ac * (thread + 1)) > len))
        return ~0ULL;

    cell += ac * thread;
    return of_read_number(cell, ac);
}
