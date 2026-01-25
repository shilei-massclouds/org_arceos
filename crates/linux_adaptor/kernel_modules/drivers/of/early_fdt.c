/*
 * early_fdt: extract parts from fdt.c
 */

#include <linux/crc32.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/libfdt_env.h>
#include <linux/memblock.h>
#include <linux/crash_dump.h>

#include <asm/setup.h>

#include "of_private.h"
#include "../libfdt/libfdt.h"
#include "adaptor.h"

void *initial_boot_params __ro_after_init;
phys_addr_t initial_boot_params_pa __ro_after_init;

/* Everything below here references initial_boot_params directly. */
int __initdata dt_root_addr_cells;
int __initdata dt_root_size_cells;

static unsigned long chosen_node_offset = -FDT_ERR_NOTFOUND;

static u32 of_fdt_crc32;

/*
 * early_init_dt_scan_root - fetch the top level address and size cells
 */
int __init early_init_dt_scan_root(void)
{
    const __be32 *prop;
    const void *fdt = initial_boot_params;
    int node = fdt_path_offset(fdt, "/");

    if (node < 0)
        return -ENODEV;

    dt_root_size_cells = OF_ROOT_NODE_SIZE_CELLS_DEFAULT;
    dt_root_addr_cells = OF_ROOT_NODE_ADDR_CELLS_DEFAULT;

    prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
    if (prop)
        dt_root_size_cells = be32_to_cpup(prop);
    pr_info("dt_root_size_cells = %x\n", dt_root_size_cells);

    prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
    if (prop)
        dt_root_addr_cells = be32_to_cpup(prop);
    pr_info("dt_root_addr_cells = %x\n", dt_root_addr_cells);

    return 0;
}

bool __init early_init_dt_scan(void *dt_virt, phys_addr_t dt_phys)
{
    bool status;

    status = early_init_dt_verify(dt_virt, dt_phys);
    if (!status)
        return false;

    early_init_dt_scan_nodes();
    return true;
}

bool __init early_init_dt_verify(void *dt_virt, phys_addr_t dt_phys)
{
    if (!dt_virt)
        return false;

    /* check device tree validity */
    if (fdt_check_header(dt_virt))
        return false;

    /* Setup flat device-tree pointer */
    initial_boot_params = dt_virt;
    initial_boot_params_pa = dt_phys;
    of_fdt_crc32 = crc32_be(~0, initial_boot_params,
                fdt_totalsize(initial_boot_params));

    /* Initialize {size,address}-cells info */
    early_init_dt_scan_root();

    return true;
}

/*
 * of_get_flat_dt_prop - Given a node in the flat blob, return the property ptr
 *
 * This function can be used within scan_flattened_dt callback to get
 * access to properties
 */
const void *__init of_get_flat_dt_prop(unsigned long node, const char *name,
                       int *size)
{
    return fdt_getprop(initial_boot_params, node, name, size);
}

void __init early_init_dt_scan_nodes(void)
{
    int rc;

    /* Retrieve various information from the /chosen node */
    rc = early_init_dt_scan_chosen(boot_command_line);
    if (rc)
        pr_warn("No chosen node found, continuing without\n");

    /* Setup memory, calling early_init_dt_add_memory_arch */
    early_init_dt_scan_memory();

    /* Handle linux,usable-memory-range property */
    early_init_dt_check_for_usable_mem_range();
}

int __init early_init_dt_scan_chosen(char *cmdline)
{
    int l, node;
    const char *p;
    const void *rng_seed;
    const void *fdt = initial_boot_params;

    node = fdt_path_offset(fdt, "/chosen");
    if (node < 0)
        node = fdt_path_offset(fdt, "/chosen@0");
    if (node < 0)
        /* Handle the cmdline config options even if no /chosen node */
        goto handle_cmdline;

    chosen_node_offset = node;

    /* Retrieve command line */
    p = of_get_flat_dt_prop(node, "bootargs", &l);
    if (p != NULL && l > 0)
        strscpy(cmdline, p, min(l, COMMAND_LINE_SIZE));

handle_cmdline:
    /*
     * CONFIG_CMDLINE is meant to be a default in case nothing else
     * managed to set the command line, unless CONFIG_CMDLINE_FORCE
     * is set in which case we override whatever was found earlier.
     */
#ifdef CONFIG_CMDLINE
#if defined(CONFIG_CMDLINE_EXTEND)
    strlcat(cmdline, " ", COMMAND_LINE_SIZE);
    strlcat(cmdline, CONFIG_CMDLINE, COMMAND_LINE_SIZE);
#elif defined(CONFIG_CMDLINE_FORCE)
    strscpy(cmdline, CONFIG_CMDLINE, COMMAND_LINE_SIZE);
#else
    /* No arguments from boot loader, use kernel's  cmdl*/
    if (!((char *)cmdline)[0])
        strscpy(cmdline, CONFIG_CMDLINE, COMMAND_LINE_SIZE);
#endif
#endif /* CONFIG_CMDLINE */

    pr_info("Command line is: [%s]\n", (char *)cmdline);

    return 0;
}

/*
 * early_init_dt_scan_memory - Look for and parse memory nodes
 */
int __init early_init_dt_scan_memory(void)
{
    int node, found_memory = 0;
    const void *fdt = initial_boot_params;

    fdt_for_each_subnode(node, fdt, 0) {
        const char *type = of_get_flat_dt_prop(node, "device_type", NULL);
        const __be32 *reg, *endp;
        int l;
        bool hotpluggable;

        /* We are scanning "memory" nodes only */
        if (type == NULL || strcmp(type, "memory") != 0)
            continue;

        if (!of_fdt_device_is_available(fdt, node))
            continue;

        reg = of_get_flat_dt_prop(node, "linux,usable-memory", &l);
        if (reg == NULL)
            reg = of_get_flat_dt_prop(node, "reg", &l);
        if (reg == NULL)
            continue;

        endp = reg + (l / sizeof(__be32));
        hotpluggable = of_get_flat_dt_prop(node, "hotpluggable", NULL);

        pr_info("memory scan node %s, reg size %d,\n",
             fdt_get_name(fdt, node, NULL), l);

        while ((endp - reg) >= (dt_root_addr_cells + dt_root_size_cells)) {
            u64 base, size;

            base = dt_mem_next_cell(dt_root_addr_cells, &reg);
            size = dt_mem_next_cell(dt_root_size_cells, &reg);

            if (size == 0)
                continue;
            pr_info(" - %llx, %llx\n", base, size);

            early_init_dt_add_memory_arch(base, size);

            found_memory = 1;

            if (!hotpluggable)
                continue;

            if (memblock_mark_hotplug(base, size))
                pr_warn("failed to mark hotplug range 0x%llx - 0x%llx\n",
                    base, base + size);
        }
    }
    return found_memory;
}

bool of_fdt_device_is_available(const void *blob, unsigned long node)
{
    const char *status = fdt_getprop(blob, node, "status", NULL);

    if (!status)
        return true;

    if (!strcmp(status, "ok") || !strcmp(status, "okay"))
        return true;

    return false;
}

u64 __init dt_mem_next_cell(int s, const __be32 **cellp)
{
    const __be32 *p = *cellp;

    *cellp = p + s;
    return of_read_number(p, s);
}

#ifndef MIN_MEMBLOCK_ADDR
#define MIN_MEMBLOCK_ADDR   __pa(PAGE_OFFSET)
#endif
#ifndef MAX_MEMBLOCK_ADDR
#define MAX_MEMBLOCK_ADDR   ((phys_addr_t)~0)
#endif

void __init __weak early_init_dt_add_memory_arch(u64 base, u64 size)
{
    const u64 phys_offset = MIN_MEMBLOCK_ADDR;

    if (size < PAGE_SIZE - (base & ~PAGE_MASK)) {
        pr_warn("Ignoring memory block 0x%llx - 0x%llx\n",
            base, base + size);
        return;
    }

    if (!PAGE_ALIGNED(base)) {
        size -= PAGE_SIZE - (base & ~PAGE_MASK);
        base = PAGE_ALIGN(base);
    }
    size &= PAGE_MASK;

    if (base > MAX_MEMBLOCK_ADDR) {
        pr_warn("Ignoring memory block 0x%llx - 0x%llx\n",
            base, base + size);
        return;
    }

    if (base + size - 1 > MAX_MEMBLOCK_ADDR) {
        pr_warn("Ignoring memory range 0x%llx - 0x%llx\n",
            ((u64)MAX_MEMBLOCK_ADDR) + 1, base + size);
        size = MAX_MEMBLOCK_ADDR - base + 1;
    }

    if (base + size < phys_offset) {
        pr_warn("Ignoring memory block 0x%llx - 0x%llx\n",
            base, base + size);
        return;
    }
    if (base < phys_offset) {
        pr_warn("Ignoring memory range 0x%llx - 0x%llx\n",
            base, phys_offset);
        size -= phys_offset - base;
        base = phys_offset;
    }
    memblock_add(base, size);
}

/*
 * The main usage of linux,usable-memory-range is for crash dump kernel.
 * Originally, the number of usable-memory regions is one. Now there may
 * be two regions, low region and high region.
 * To make compatibility with existing user-space and older kdump, the low
 * region is always the last range of linux,usable-memory-range if exist.
 */
#define MAX_USABLE_RANGES       2

/**
 * early_init_dt_check_for_usable_mem_range - Decode usable memory range
 * location from flat tree
 */
void __init early_init_dt_check_for_usable_mem_range(void)
{
    struct memblock_region rgn[MAX_USABLE_RANGES] = {0};
    const __be32 *prop, *endp;
    int len, i;
    unsigned long node = chosen_node_offset;

    if ((long)node < 0)
        return;

    pr_debug("Looking for usable-memory-range property... ");

    prop = of_get_flat_dt_prop(node, "linux,usable-memory-range", &len);
    if (!prop || (len % (dt_root_addr_cells + dt_root_size_cells)))
        return;

    endp = prop + (len / sizeof(__be32));
    for (i = 0; i < MAX_USABLE_RANGES && prop < endp; i++) {
        rgn[i].base = dt_mem_next_cell(dt_root_addr_cells, &prop);
        rgn[i].size = dt_mem_next_cell(dt_root_size_cells, &prop);

        pr_debug("cap_mem_regions[%d]: base=%pa, size=%pa\n",
             i, &rgn[i].base, &rgn[i].size);
    }

    memblock_cap_memory_range(rgn[0].base, rgn[0].size);
    for (i = 1; i < MAX_USABLE_RANGES && rgn[i].size; i++)
        memblock_add(rgn[i].base, rgn[i].size);
}

const char * __init of_flat_dt_get_machine_name(void)
{
    const char *name;
    unsigned long dt_root = of_get_flat_dt_root();

    name = of_get_flat_dt_prop(dt_root, "model", NULL);
    if (!name)
        name = of_get_flat_dt_prop(dt_root, "compatible", NULL);
    return name;
}

/*
 * of_get_flat_dt_root - find the root node in the flat blob
 */
unsigned long __init of_get_flat_dt_root(void)
{
    return 0;
}

/*
 * fdt_reserve_elfcorehdr() - reserves memory for elf core header
 *
 * This function reserves the memory occupied by an elf core header
 * described in the device tree. This region contains all the
 * information about primary kernel's core image and is used by a dump
 * capture kernel to access the system memory on primary kernel.
 */
static void __init fdt_reserve_elfcorehdr(void)
{
    if (!IS_ENABLED(CONFIG_CRASH_DUMP) || !elfcorehdr_size)
        return;

    if (memblock_is_region_reserved(elfcorehdr_addr, elfcorehdr_size)) {
        pr_warn("elfcorehdr is overlapped\n");
        return;
    }

    memblock_reserve(elfcorehdr_addr, elfcorehdr_size);

    pr_info("Reserving %llu KiB of memory at 0x%llx for elfcorehdr\n",
        elfcorehdr_size >> 10, elfcorehdr_addr);
}

/**
 * early_init_fdt_scan_reserved_mem() - create reserved memory regions
 *
 * This function grabs memory from early allocator for device exclusive use
 * defined in device tree structures. It should be called by arch specific code
 * once the early allocator (i.e. memblock) has been fully activated.
 */
void __init early_init_fdt_scan_reserved_mem(void)
{
    int n;
    u64 base, size;

    if (!initial_boot_params)
        return;

    fdt_scan_reserved_mem();
    fdt_reserve_elfcorehdr();

    /* Process header /memreserve/ fields */
    for (n = 0; ; n++) {
        fdt_get_mem_rsv(initial_boot_params, n, &base, &size);
        if (!size)
            break;
        memblock_reserve(base, size);
    }
}
