#define pr_fmt(fmt) "OF: fdt: " fmt

#include <linux/crash_dump.h>
#include <linux/crc32.h>
#include <linux/kernel.h>
#include <linux/initrd.h>
#include <linux/memblock.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/libfdt_env.h>
#include <linux/debugfs.h>
#include <linux/serial_core.h>
#include <linux/sysfs.h>
#include <linux/random.h>

#include <asm/setup.h>  /* for COMMAND_LINE_SIZE */
#include <asm/page.h>

#include "of_private.h"
#include "../libfdt/libfdt.h"
#include "../adaptor.h"

void *initial_boot_params __ro_after_init;
phys_addr_t initial_boot_params_pa __ro_after_init;

/* Everything below here references initial_boot_params directly. */
int __initdata dt_root_addr_cells;
int __initdata dt_root_size_cells;

static void * __init early_init_dt_alloc_memory_arch(u64 size, u64 align)
{
    void *ptr = memblock_alloc(size, align);

    if (!ptr)
        panic("%s: Failed to allocate %llu bytes align=0x%llx\n",
              __func__, size, align);

    return ptr;
}

static void *unflatten_dt_alloc(void **mem, unsigned long size,
                       unsigned long align)
{
    void *res;

    *mem = PTR_ALIGN(*mem, align);
    res = *mem;
    *mem += size;

    return res;
}

static void populate_properties(const void *blob,
                int offset,
                void **mem,
                struct device_node *np,
                const char *nodename,
                bool dryrun)
{
    struct property *pp, **pprev = NULL;
    int cur;
    bool has_name = false;

    pprev = &np->properties;
    for (cur = fdt_first_property_offset(blob, offset);
         cur >= 0;
         cur = fdt_next_property_offset(blob, cur)) {
        const __be32 *val;
        const char *pname;
        u32 sz;

        val = fdt_getprop_by_offset(blob, cur, &pname, &sz);
        if (!val) {
            pr_warn("Cannot locate property at 0x%x\n", cur);
            continue;
        }

        if (!pname) {
            pr_warn("Cannot find property name at 0x%x\n", cur);
            continue;
        }

        if (!strcmp(pname, "name"))
            has_name = true;

        pp = unflatten_dt_alloc(mem, sizeof(struct property),
                    __alignof__(struct property));
        if (dryrun)
            continue;

        /* We accept flattened tree phandles either in
         * ePAPR-style "phandle" properties, or the
         * legacy "linux,phandle" properties.  If both
         * appear and have different values, things
         * will get weird. Don't do that.
         */
        if (!strcmp(pname, "phandle") ||
            !strcmp(pname, "linux,phandle")) {
            if (!np->phandle)
                np->phandle = be32_to_cpup(val);
        }

        /* And we process the "ibm,phandle" property
         * used in pSeries dynamic device tree
         * stuff
         */
        if (!strcmp(pname, "ibm,phandle"))
            np->phandle = be32_to_cpup(val);

        pp->name   = (char *)pname;
        pp->length = sz;
        pp->value  = (__be32 *)val;
        *pprev     = pp;
        pprev      = &pp->next;
    }

    /* With version 0x10 we may not have the name property,
     * recreate it here from the unit name if absent
     */
    if (!has_name) {
        const char *p = nodename, *ps = p, *pa = NULL;
        int len;

        while (*p) {
            if ((*p) == '@')
                pa = p;
            else if ((*p) == '/')
                ps = p + 1;
            p++;
        }

        if (pa < ps)
            pa = p;
        len = (pa - ps) + 1;
        pp = unflatten_dt_alloc(mem, sizeof(struct property) + len,
                    __alignof__(struct property));
        if (!dryrun) {
            pp->name   = "name";
            pp->length = len;
            pp->value  = pp + 1;
            *pprev     = pp;
            memcpy(pp->value, ps, len - 1);
            ((char *)pp->value)[len - 1] = 0;
            pr_debug("fixed up name for %s -> %s\n",
                 nodename, (char *)pp->value);
        }
    }
}

static int populate_node(const void *blob,
              int offset,
              void **mem,
              struct device_node *dad,
              struct device_node **pnp,
              bool dryrun)
{
    struct device_node *np;
    const char *pathp;
    int len;

    pathp = fdt_get_name(blob, offset, &len);
    if (!pathp) {
        *pnp = NULL;
        return len;
    }

    len++;

    np = unflatten_dt_alloc(mem, sizeof(struct device_node) + len,
                __alignof__(struct device_node));
    if (!dryrun) {
        char *fn;
        of_node_init(np);
        np->full_name = fn = ((char *)np) + sizeof(*np);

        memcpy(fn, pathp, len);

        if (dad != NULL) {
            np->parent = dad;
            np->sibling = dad->child;
            dad->child = np;
        }
    }

    populate_properties(blob, offset, mem, np, pathp, dryrun);
    if (!dryrun) {
        np->name = of_get_property(np, "name", NULL);
        if (!np->name)
            np->name = "<NULL>";
    }

    *pnp = np;
    return 0;
}

static void reverse_nodes(struct device_node *parent)
{
    struct device_node *child, *next;

    /* In-depth first */
    child = parent->child;
    while (child) {
        reverse_nodes(child);

        child = child->sibling;
    }

    /* Reverse the nodes in the child list */
    child = parent->child;
    parent->child = NULL;
    while (child) {
        next = child->sibling;

        child->sibling = parent->child;
        parent->child = child;
        child = next;
    }
}

/**
 * unflatten_dt_nodes - Alloc and populate a device_node from the flat tree
 * @blob: The parent device tree blob
 * @mem: Memory chunk to use for allocating device nodes and properties
 * @dad: Parent struct device_node
 * @nodepp: The device_node tree created by the call
 *
 * Return: The size of unflattened device tree or error code
 */
static int unflatten_dt_nodes(const void *blob,
                  void *mem,
                  struct device_node *dad,
                  struct device_node **nodepp)
{
    struct device_node *root;
    int offset = 0, depth = 0, initial_depth = 0;
#define FDT_MAX_DEPTH   64
    struct device_node *nps[FDT_MAX_DEPTH];
    void *base = mem;
    bool dryrun = !base;
    int ret;

    if (nodepp)
        *nodepp = NULL;

    /*
     * We're unflattening device sub-tree if @dad is valid. There are
     * possibly multiple nodes in the first level of depth. We need
     * set @depth to 1 to make fdt_next_node() happy as it bails
     * immediately when negative @depth is found. Otherwise, the device
     * nodes except the first one won't be unflattened successfully.
     */
    if (dad)
        depth = initial_depth = 1;

    root = dad;
    nps[depth] = dad;

    for (offset = 0;
         offset >= 0 && depth >= initial_depth;
         offset = fdt_next_node(blob, offset, &depth)) {
        if (WARN_ON_ONCE(depth >= FDT_MAX_DEPTH - 1))
            continue;

        if (!IS_ENABLED(CONFIG_OF_KOBJ) &&
            !of_fdt_device_is_available(blob, offset))
            continue;

        ret = populate_node(blob, offset, &mem, nps[depth],
                   &nps[depth+1], dryrun);
        if (ret < 0)
            return ret;

        if (!dryrun && nodepp && !*nodepp)
            *nodepp = nps[depth+1];
        if (!dryrun && !root)
            root = nps[depth+1];
    }

    if (offset < 0 && offset != -FDT_ERR_NOTFOUND) {
        pr_err("Error %d processing FDT\n", offset);
        return -EINVAL;
    }

    /*
     * Reverse the child list. Some drivers assumes node order matches .dts
     * node order
     */
    if (!dryrun)
        reverse_nodes(root);

    return mem - base;
}

/**
 * __unflatten_device_tree - create tree of device_nodes from flat blob
 * @blob: The blob to expand
 * @dad: Parent device node
 * @mynodes: The device_node tree created by the call
 * @dt_alloc: An allocator that provides a virtual address to memory
 * for the resulting tree
 * @detached: if true set OF_DETACHED on @mynodes
 *
 * unflattens a device-tree, creating the tree of struct device_node. It also
 * fills the "name" and "type" pointers of the nodes so the normal device-tree
 * walking functions can be used.
 *
 * Return: NULL on failure or the memory chunk containing the unflattened
 * device tree on success.
 */
void *__unflatten_device_tree(const void *blob,
                  struct device_node *dad,
                  struct device_node **mynodes,
                  void *(*dt_alloc)(u64 size, u64 align),
                  bool detached)
{
    int size;
    void *mem;
    int ret;

    if (mynodes)
        *mynodes = NULL;

    pr_debug(" -> unflatten_device_tree()\n");

    if (!blob) {
        pr_debug("No device tree pointer\n");
        return NULL;
    }

    pr_debug("Unflattening device tree:\n");
    pr_debug("magic: %08x\n", fdt_magic(blob));
    pr_debug("size: %08x\n", fdt_totalsize(blob));
    pr_debug("version: %08x\n", fdt_version(blob));

    if (fdt_check_header(blob)) {
        pr_err("Invalid device tree blob header\n");
        return NULL;
    }

    /* First pass, scan for size */
    size = unflatten_dt_nodes(blob, NULL, dad, NULL);
    if (size <= 0)
        return NULL;

    size = ALIGN(size, 4);
    pr_debug("  size is %d, allocating...\n", size);

    /* Allocate memory for the expanded device tree */
    mem = dt_alloc(size + 4, __alignof__(struct device_node));
    if (!mem)
        return NULL;

    memset(mem, 0, size);

    *(__be32 *)(mem + size) = cpu_to_be32(0xdeadbeef);

    pr_debug("  unflattening %p...\n", mem);

    /* Second pass, do actual unflattening */
    ret = unflatten_dt_nodes(blob, mem, dad, mynodes);

    if (be32_to_cpup(mem + size) != 0xdeadbeef)
        pr_warn("End of tree marker overwritten: %08x\n",
            be32_to_cpup(mem + size));

    if (ret <= 0)
        return NULL;

    if (detached && mynodes && *mynodes) {
        of_node_set_flag(*mynodes, OF_DETACHED);
        pr_debug("unflattened tree is detached\n");
    }

    pr_debug(" <- unflatten_device_tree()\n");
    return mem;
}

/**
 * unflatten_device_tree - create tree of device_nodes from flat blob
 *
 * unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 */
void __init unflatten_device_tree(void)
{
    void *fdt = initial_boot_params;
    printk("%s: (%lx)\n", __func__, initial_boot_params);

    /* Save the statically-placed regions in the reserved_mem array */
    fdt_scan_reserved_mem_reg_nodes();

    /* Populate an empty root node when bootloader doesn't provide one */
    if (!fdt) {
        PANIC("No fdt.");
    }

    __unflatten_device_tree(fdt, NULL, &of_root,
                early_init_dt_alloc_memory_arch, false);

    /* Get pointer to "/chosen" and "/aliases" nodes for use everywhere */
    of_alias_scan(early_init_dt_alloc_memory_arch);

    unittest_unflatten_overlay_base();
}

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
    pr_debug("dt_root_size_cells = %x\n", dt_root_size_cells);

    prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
    if (prop)
        dt_root_addr_cells = be32_to_cpup(prop);
    pr_debug("dt_root_addr_cells = %x\n", dt_root_addr_cells);

    return 0;
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

bool of_fdt_device_is_available(const void *blob, unsigned long node)
{
    const char *status = fdt_getprop(blob, node, "status", NULL);

    if (!status)
        return true;

    if (!strcmp(status, "ok") || !strcmp(status, "okay"))
        return true;

    return false;
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

    pr_debug("Command line is: %s\n", (char *)cmdline);

    return 0;
}

u64 __init dt_mem_next_cell(int s, const __be32 **cellp)
{
    const __be32 *p = *cellp;

    *cellp = p + s;
    return of_read_number(p, s);
}

bool __init early_init_dt_verify(void *dt_virt, phys_addr_t dt_phys)
{
    if (!dt_virt)
        return false;

    printk("virt(%lx) phys(%lx)\n", dt_virt, dt_phys);
    /* check device tree validity */
    if (fdt_check_header(dt_virt))
        return false;

    /* Setup flat device-tree pointer */
    initial_boot_params = dt_virt;
    initial_boot_params_pa = dt_phys;
#if 0
    of_fdt_crc32 = crc32_be(~0, initial_boot_params,
                fdt_totalsize(initial_boot_params));
#endif

    /* Initialize {size,address}-cells info */
    early_init_dt_scan_root();

    return true;
}
