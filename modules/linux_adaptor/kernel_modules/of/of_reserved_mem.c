#define pr_fmt(fmt) "OF: reserved mem: " fmt

#include <linux/err.h>
#include <linux/libfdt.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_platform.h>
#include <linux/mm.h>
#include <linux/sizes.h>
#include <linux/of_reserved_mem.h>
#include <linux/sort.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/kmemleak.h>
#include <linux/cma.h>

#include "of_private.h"
#include "../adaptor.h"

static struct reserved_mem reserved_mem[MAX_RESERVED_REGIONS];
static int reserved_mem_count;

static int __init __rmem_cmp(const void *a, const void *b)
{
    const struct reserved_mem *ra = a, *rb = b;

    if (ra->base < rb->base)
        return -1;

    if (ra->base > rb->base)
        return 1;

    /*
     * Put the dynamic allocations (address == 0, size == 0) before static
     * allocations at address 0x0 so that overlap detection works
     * correctly.
     */
    if (ra->size < rb->size)
        return -1;
    if (ra->size > rb->size)
        return 1;

    if (ra->fdt_node < rb->fdt_node)
        return -1;
    if (ra->fdt_node > rb->fdt_node)
        return 1;

    return 0;
}

/*
 * __reserved_mem_check_root() - check if #size-cells, #address-cells provided
 * in /reserved-memory matches the values supported by the current implementation,
 * also check if ranges property has been provided
 */
static int __init __reserved_mem_check_root(unsigned long node)
{
    const __be32 *prop;

    prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
    if (!prop || be32_to_cpup(prop) != dt_root_size_cells)
        return -EINVAL;

    prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
    if (!prop || be32_to_cpup(prop) != dt_root_addr_cells)
        return -EINVAL;

    prop = of_get_flat_dt_prop(node, "ranges", NULL);
    if (!prop)
        return -EINVAL;
    return 0;
}

static void __init __rmem_check_for_overlap(void)
{
    int i;

    if (reserved_mem_count < 2)
        return;

    sort(reserved_mem, reserved_mem_count, sizeof(reserved_mem[0]),
         __rmem_cmp, NULL);
    for (i = 0; i < reserved_mem_count - 1; i++) {
        struct reserved_mem *this, *next;

        this = &reserved_mem[i];
        next = &reserved_mem[i + 1];

        if (this->base + this->size > next->base) {
            phys_addr_t this_end, next_end;

            this_end = this->base + this->size;
            next_end = next->base + next->size;
            pr_err("OVERLAP DETECTED!\n%s (%pa--%pa) overlaps with %s (%pa--%pa)\n",
                   this->name, &this->base, &this_end,
                   next->name, &next->base, &next_end);
        }
    }
}

/**
 * fdt_init_reserved_mem_node() - Initialize a reserved memory region
 * @rmem: reserved_mem struct of the memory region to be initialized.
 *
 * This function is used to call the region specific initialization
 * function for a reserved memory region.
 */
static void __init fdt_init_reserved_mem_node(struct reserved_mem *rmem)
{
    pr_notice("%s: No impl.", __func__);
}

/*
 * fdt_reserved_mem_save_node() - save fdt node for second pass initialization
 */
static void __init fdt_reserved_mem_save_node(unsigned long node, const char *uname,
                          phys_addr_t base, phys_addr_t size)
{
    struct reserved_mem *rmem = &reserved_mem[reserved_mem_count];

    if (reserved_mem_count == ARRAY_SIZE(reserved_mem)) {
        pr_err("not enough space for all defined regions.\n");
        return;
    }

    rmem->fdt_node = node;
    rmem->name = uname;
    rmem->base = base;
    rmem->size = size;

    /* Call the region specific initialization function */
    fdt_init_reserved_mem_node(rmem);

    reserved_mem_count++;
    return;
}

/**
 * fdt_scan_reserved_mem_reg_nodes() - Store info for the "reg" defined
 * reserved memory regions.
 *
 * This function is used to scan through the DT and store the
 * information for the reserved memory regions that are defined using
 * the "reg" property. The region node number, name, base address, and
 * size are all stored in the reserved_mem array by calling the
 * fdt_reserved_mem_save_node() function.
 */
void __init fdt_scan_reserved_mem_reg_nodes(void)
{
    int t_len = (dt_root_addr_cells + dt_root_size_cells) * sizeof(__be32);
    const void *fdt = initial_boot_params;
    phys_addr_t base, size;
    const __be32 *prop;
    int node, child;
    int len;

    if (!fdt)
        return;

    node = fdt_path_offset(fdt, "/reserved-memory");
    if (node < 0) {
        pr_info("Reserved memory: No reserved-memory node in the DT\n");
        return;
    }

    if (__reserved_mem_check_root(node)) {
        pr_err("Reserved memory: unsupported node format, ignoring\n");
        return;
    }

    fdt_for_each_subnode(child, fdt, node) {
        const char *uname;

        prop = of_get_flat_dt_prop(child, "reg", &len);
        if (!prop)
            continue;
        if (!of_fdt_device_is_available(fdt, child))
            continue;

        uname = fdt_get_name(fdt, child, NULL);
        if (len && len % t_len != 0) {
            pr_err("Reserved memory: invalid reg property in '%s', skipping node.\n",
                   uname);
            continue;
        }

        printk("%s: uname(%s)\n", __func__, uname);
        if (len > t_len)
            pr_warn("%s() ignores %d regions in node '%s'\n",
                __func__, len / t_len - 1, uname);

        base = dt_mem_next_cell(dt_root_addr_cells, &prop);
        size = dt_mem_next_cell(dt_root_size_cells, &prop);

        if (size)
            fdt_reserved_mem_save_node(child, uname, base, size);
    }

    /* check for overlapping reserved regions */
    __rmem_check_for_overlap();
}
