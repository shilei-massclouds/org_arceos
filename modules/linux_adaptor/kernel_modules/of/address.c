#define pr_fmt(fmt) "OF: " fmt

#include <linux/device.h>
#include <linux/fwnode.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/logic_pio.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/dma-direct.h> /* for bus_dma_region */

#include "of_private.h"
#include "../adaptor.h"

/* Max address size we deal with */
#define OF_MAX_ADDR_CELLS   4
#define OF_CHECK_ADDR_COUNT(na) ((na) > 0 && (na) <= OF_MAX_ADDR_CELLS)
#define OF_CHECK_COUNTS(na, ns) (OF_CHECK_ADDR_COUNT(na) && (ns) > 0)

/* Callbacks for bus specific translators */
struct of_bus {
    const char  *name;
    const char  *addresses;
    int     (*match)(struct device_node *parent);
    void        (*count_cells)(struct device_node *child,
                       int *addrc, int *sizec);
    u64     (*map)(__be32 *addr, const __be32 *range,
                int na, int ns, int pna, int fna);
    int     (*translate)(__be32 *addr, u64 offset, int na);
    int     flag_cells;
    unsigned int    (*get_flags)(const __be32 *addr);
};

/* Debug utility */
#ifdef DEBUG
static void of_dump_addr(const char *s, const __be32 *addr, int na)
{
    pr_debug("%s", s);
    while (na--)
        pr_cont(" %08x", be32_to_cpu(*(addr++)));
    pr_cont("\n");
}
#else
static void of_dump_addr(const char *s, const __be32 *addr, int na) { }
#endif

/*
 * Default translator (generic bus)
 */

static void of_bus_default_count_cells(struct device_node *dev,
                       int *addrc, int *sizec)
{
    if (addrc)
        *addrc = of_n_addr_cells(dev);
    if (sizec)
        *sizec = of_n_size_cells(dev);
}

static u64 of_bus_default_map(__be32 *addr, const __be32 *range,
        int na, int ns, int pna, int fna)
{
    u64 cp, s, da;

    cp = of_read_number(range + fna, na - fna);
    s  = of_read_number(range + na + pna, ns);
    da = of_read_number(addr + fna, na - fna);

    pr_debug("default map, cp=%llx, s=%llx, da=%llx\n", cp, s, da);

    if (da < cp || da >= (cp + s))
        return OF_BAD_ADDR;
    return da - cp;
}

static int of_bus_default_translate(__be32 *addr, u64 offset, int na)
{
    u64 a = of_read_number(addr, na);
    memset(addr, 0, na * 4);
    a += offset;
    if (na > 1)
        addr[na - 2] = cpu_to_be32(a >> 32);
    addr[na - 1] = cpu_to_be32(a & 0xffffffffu);

    return 0;
}

static unsigned int of_bus_default_flags_get_flags(const __be32 *addr)
{
    return of_read_number(addr, 1);
}

static u64 of_bus_default_flags_map(__be32 *addr, const __be32 *range, int na,
                    int ns, int pna, int fna)
{
    /* Check that flags match */
    if (*addr != *range)
        return OF_BAD_ADDR;

    return of_bus_default_map(addr, range, na, ns, pna, fna);
}

static unsigned int of_bus_default_get_flags(const __be32 *addr)
{
    return IORESOURCE_MEM;
}

static int of_bus_default_flags_translate(__be32 *addr, u64 offset, int na)
{
    /* Keep "flags" part (high cell) in translated address */
    return of_bus_default_translate(addr + 1, offset, na - 1);
}

/*
 * PCI bus specific translator
 */

static unsigned int of_bus_pci_get_flags(const __be32 *addr)
{
    unsigned int flags = 0;
    u32 w = be32_to_cpup(addr);

    if (!IS_ENABLED(CONFIG_PCI))
        return 0;

    switch((w >> 24) & 0x03) {
    case 0x01:
        flags |= IORESOURCE_IO;
        break;
    case 0x02: /* 32 bits */
        flags |= IORESOURCE_MEM;
        break;

    case 0x03: /* 64 bits */
        flags |= IORESOURCE_MEM | IORESOURCE_MEM_64;
        break;
    }
    if (w & 0x40000000)
        flags |= IORESOURCE_PREFETCH;
    return flags;
}

static bool of_node_is_pcie(struct device_node *np)
{
    bool is_pcie = of_node_name_eq(np, "pcie");

    if (is_pcie)
        pr_warn_once("%pOF: Missing device_type\n", np);

    return is_pcie;
}

static int of_bus_pci_match(struct device_node *np)
{
    /*
     * "pciex" is PCI Express
     * "vci" is for the /chaos bridge on 1st-gen PCI powermacs
     * "ht" is hypertransport
     *
     * If none of the device_type match, and that the node name is
     * "pcie", accept the device as PCI (with a warning).
     */
    return of_node_is_type(np, "pci") || of_node_is_type(np, "pciex") ||
        of_node_is_type(np, "vci") || of_node_is_type(np, "ht") ||
        of_node_is_pcie(np);
}

static void of_bus_pci_count_cells(struct device_node *np,
                   int *addrc, int *sizec)
{
    if (addrc)
        *addrc = 3;
    if (sizec)
        *sizec = 2;
}

static u64 of_bus_pci_map(__be32 *addr, const __be32 *range, int na, int ns,
        int pna, int fna)
{
    unsigned int af, rf;

    af = of_bus_pci_get_flags(addr);
    rf = of_bus_pci_get_flags(range);

    /* Check address type match */
    if ((af ^ rf) & (IORESOURCE_MEM | IORESOURCE_IO))
        return OF_BAD_ADDR;

    return of_bus_default_map(addr, range, na, ns, pna, fna);
}

/*
 * ISA bus specific translator
 */

static int of_bus_isa_match(struct device_node *np)
{
    return of_node_name_eq(np, "isa");
}

static void of_bus_isa_count_cells(struct device_node *child,
                   int *addrc, int *sizec)
{
    if (addrc)
        *addrc = 2;
    if (sizec)
        *sizec = 1;
}

static u64 of_bus_isa_map(__be32 *addr, const __be32 *range, int na, int ns,
        int pna, int fna)
{
    /* Check address type match */
    if ((addr[0] ^ range[0]) & cpu_to_be32(1))
        return OF_BAD_ADDR;

    return of_bus_default_map(addr, range, na, ns, pna, fna);
}

static unsigned int of_bus_isa_get_flags(const __be32 *addr)
{
    unsigned int flags = 0;
    u32 w = be32_to_cpup(addr);

    if (w & 1)
        flags |= IORESOURCE_IO;
    else
        flags |= IORESOURCE_MEM;
    return flags;
}

static int of_bus_default_flags_match(struct device_node *np)
{
    return of_bus_n_addr_cells(np) == 3;
}


/*
 * Array of bus specific translators
 */

static struct of_bus of_busses[] = {
#ifdef CONFIG_PCI
    /* PCI */
    {
        .name = "pci",
        .addresses = "assigned-addresses",
        .match = of_bus_pci_match,
        .count_cells = of_bus_pci_count_cells,
        .map = of_bus_pci_map,
        .translate = of_bus_default_flags_translate,
        .flag_cells = 1,
        .get_flags = of_bus_pci_get_flags,
    },
#endif /* CONFIG_PCI */
    /* ISA */
    {
        .name = "isa",
        .addresses = "reg",
        .match = of_bus_isa_match,
        .count_cells = of_bus_isa_count_cells,
        .map = of_bus_isa_map,
        .translate = of_bus_default_flags_translate,
        .flag_cells = 1,
        .get_flags = of_bus_isa_get_flags,
    },
    /* Default with flags cell */
    {
        .name = "default-flags",
        .addresses = "reg",
        .match = of_bus_default_flags_match,
        .count_cells = of_bus_default_count_cells,
        .map = of_bus_default_flags_map,
        .translate = of_bus_default_flags_translate,
        .flag_cells = 1,
        .get_flags = of_bus_default_flags_get_flags,
    },
    /* Default */
    {
        .name = "default",
        .addresses = "reg",
        .match = NULL,
        .count_cells = of_bus_default_count_cells,
        .map = of_bus_default_map,
        .translate = of_bus_default_translate,
        .get_flags = of_bus_default_get_flags,
    },
};

static struct of_bus *of_match_bus(struct device_node *np)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(of_busses); i++)
        if (!of_busses[i].match || of_busses[i].match(np))
            return &of_busses[i];
    BUG();
    return NULL;
}

static int __of_address_resource_bounds(struct resource *r, u64 start, u64 size)
{
    if (overflows_type(start, r->start))
        return -EOVERFLOW;

    r->start = start;

    if (!size)
        r->end = wrapping_sub(typeof(r->end), r->start, 1);
    else if (size && check_add_overflow(r->start, size - 1, &r->end))
        return -EOVERFLOW;

    return 0;
}

/**
 * of_mmio_is_nonposted - Check if device uses non-posted MMIO
 * @np: device node
 *
 * Returns true if the "nonposted-mmio" property was found for
 * the device's bus.
 *
 * This is currently only enabled on builds that support Apple ARM devices, as
 * an optimization.
 */
static bool of_mmio_is_nonposted(struct device_node *np)
{
    if (!IS_ENABLED(CONFIG_ARCH_APPLE))
        return false;

    struct device_node *parent __free(device_node) = of_get_parent(np);
    if (!parent)
        return false;

    return of_property_read_bool(parent, "nonposted-mmio");
}

const __be32 *__of_get_address(struct device_node *dev, int index, int bar_no,
                   u64 *size, unsigned int *flags)
{
    const __be32 *prop;
    unsigned int psize;
    struct device_node *parent __free(device_node) = of_get_parent(dev);
    struct of_bus *bus;
    int onesize, i, na, ns;

    if (parent == NULL)
        return NULL;

    /* match the parent's bus type */
    bus = of_match_bus(parent);
    if (strcmp(bus->name, "pci") && (bar_no >= 0))
        return NULL;

    bus->count_cells(dev, &na, &ns);
    if (!OF_CHECK_ADDR_COUNT(na))
        return NULL;

    /* Get "reg" or "assigned-addresses" property */
    prop = of_get_property(dev, bus->addresses, &psize);
    if (prop == NULL)
        return NULL;
    psize /= 4;

    onesize = na + ns;
    for (i = 0; psize >= onesize; psize -= onesize, prop += onesize, i++) {
        u32 val = be32_to_cpu(prop[0]);
        /* PCI bus matches on BAR number instead of index */
        if (((bar_no >= 0) && ((val & 0xff) == ((bar_no * 4) + PCI_BASE_ADDRESS_0))) ||
            ((index >= 0) && (i == index))) {
            if (size)
                *size = of_read_number(prop + na, ns);
            if (flags)
                *flags = bus->get_flags(prop);
            return prop;
        }
    }
    return NULL;
}

static u64 of_translate_ioport(struct device_node *dev, const __be32 *in_addr,
            u64 size)
{
    PANIC("");
}

static int __of_address_to_resource(struct device_node *dev, int index, int bar_no,
        struct resource *r)
{
    u64 taddr;
    const __be32    *addrp;
    u64     size;
    unsigned int    flags;
    const char  *name = NULL;

    addrp = __of_get_address(dev, index, bar_no, &size, &flags);
    if (addrp == NULL)
        return -EINVAL;

    /* Get optional "reg-names" property to add a name to a resource */
    if (index >= 0)
        of_property_read_string_index(dev, "reg-names", index, &name);

    if (flags & IORESOURCE_MEM)
        taddr = of_translate_address(dev, addrp);
    else if (flags & IORESOURCE_IO)
        taddr = of_translate_ioport(dev, addrp, size);
    else
        return -EINVAL;

    if (taddr == OF_BAD_ADDR)
        return -EINVAL;
    memset(r, 0, sizeof(struct resource));

    if (of_mmio_is_nonposted(dev))
        flags |= IORESOURCE_MEM_NONPOSTED;

    r->flags = flags;
    r->name = name ? name : dev->full_name;

    return __of_address_resource_bounds(r, taddr, size);
}

/**
 * of_address_to_resource - Translate device tree address and return as resource
 * @dev:    Caller's Device Node
 * @index:  Index into the array
 * @r:      Pointer to resource array
 *
 * Returns -EINVAL if the range cannot be converted to resource.
 *
 * Note that if your address is a PIO address, the conversion will fail if
 * the physical address can't be internally converted to an IO token with
 * pci_address_to_pio(), that is because it's either called too early or it
 * can't be matched to any host bridge IO space
 */
int of_address_to_resource(struct device_node *dev, int index,
               struct resource *r)
{
    return __of_address_to_resource(dev, index, -1, r);
}

/**
 * of_iomap - Maps the memory mapped IO for a given device_node
 * @np:     the device whose io range will be mapped
 * @index:  index of the io range
 *
 * Returns a pointer to the mapped memory
 */
void __iomem *of_iomap(struct device_node *np, int index)
{
    void *ret;
    struct resource res;

    if (of_address_to_resource(np, index, &res))
        return NULL;

    pr_debug("%s: (%s) res [%lx,%lx](%lx)\n", __func__, np->name, res.start, res.end, res.flags);

    ret = __va(res.start);
    return ret;
}

static int of_empty_ranges_quirk(struct device_node *np)
{
    return false;
}

static int of_translate_one(struct device_node *parent, struct of_bus *bus,
                struct of_bus *pbus, __be32 *addr,
                int na, int ns, int pna, const char *rprop)
{
    const __be32 *ranges;
    unsigned int rlen;
    int rone;
    u64 offset = OF_BAD_ADDR;

    /*
     * Normally, an absence of a "ranges" property means we are
     * crossing a non-translatable boundary, and thus the addresses
     * below the current cannot be converted to CPU physical ones.
     * Unfortunately, while this is very clear in the spec, it's not
     * what Apple understood, and they do have things like /uni-n or
     * /ht nodes with no "ranges" property and a lot of perfectly
     * useable mapped devices below them. Thus we treat the absence of
     * "ranges" as equivalent to an empty "ranges" property which means
     * a 1:1 translation at that level. It's up to the caller not to try
     * to translate addresses that aren't supposed to be translated in
     * the first place. --BenH.
     *
     * As far as we know, this damage only exists on Apple machines, so
     * This code is only enabled on powerpc. --gcl
     *
     * This quirk also applies for 'dma-ranges' which frequently exist in
     * child nodes without 'dma-ranges' in the parent nodes. --RobH
     */
    ranges = of_get_property(parent, rprop, &rlen);
    if (ranges == NULL && !of_empty_ranges_quirk(parent) &&
        strcmp(rprop, "dma-ranges")) {
        pr_debug("no ranges; cannot translate\n");
        return 1;
    }
    if (ranges == NULL || rlen == 0) {
        offset = of_read_number(addr, na);
        /* set address to zero, pass flags through */
        memset(addr + pbus->flag_cells, 0, (pna - pbus->flag_cells) * 4);
        pr_debug("empty ranges; 1:1 translation\n");
        goto finish;
    }

    pr_debug("walking ranges...\n");

    /* Now walk through the ranges */
    rlen /= 4;
    rone = na + pna + ns;
    for (; rlen >= rone; rlen -= rone, ranges += rone) {
        offset = bus->map(addr, ranges, na, ns, pna, bus->flag_cells);
        if (offset != OF_BAD_ADDR)
            break;
    }
    if (offset == OF_BAD_ADDR) {
        pr_debug("not found !\n");
        return 1;
    }
    memcpy(addr, ranges + na, 4 * pna);

 finish:
    of_dump_addr("parent translation for:", addr, pna);
    pr_debug("with offset: %llx\n", offset);

    /* Translate it into parent bus space */
    return pbus->translate(addr, offset, pna);
}

/*
 * Translate an address from the device-tree into a CPU physical address,
 * this walks up the tree and applies the various bus mappings on the
 * way.
 *
 * Note: We consider that crossing any level with #size-cells == 0 to mean
 * that translation is impossible (that is we are not dealing with a value
 * that can be mapped to a cpu physical address). This is not really specified
 * that way, but this is traditionally the way IBM at least do things
 *
 * Whenever the translation fails, the *host pointer will be set to the
 * device that had registered logical PIO mapping, and the return code is
 * relative to that node.
 */
static u64 __of_translate_address(struct device_node *node,
                  struct device_node *(*get_parent)(const struct device_node *),
                  const __be32 *in_addr, const char *rprop,
                  struct device_node **host)
{
    struct device_node *dev __free(device_node) = of_node_get(node);
    struct device_node *parent __free(device_node) = get_parent(dev);
    struct of_bus *bus, *pbus;
    __be32 addr[OF_MAX_ADDR_CELLS];
    int na, ns, pna, pns;

    pr_debug("** translation for device %pOF **\n", dev);

    *host = NULL;

    if (parent == NULL)
        return OF_BAD_ADDR;
    bus = of_match_bus(parent);

    /* Count address cells & copy address locally */
    bus->count_cells(dev, &na, &ns);
    if (!OF_CHECK_COUNTS(na, ns)) {
        pr_debug("Bad cell count for %pOF\n", dev);
        return OF_BAD_ADDR;
    }
    memcpy(addr, in_addr, na * 4);

    pr_debug("bus is %s (na=%d, ns=%d) on %pOF\n",
        bus->name, na, ns, parent);
    of_dump_addr("translating address:", addr, na);

    /* Translate */
    for (;;) {
        struct logic_pio_hwaddr *iorange;

        /* Switch to parent bus */
        of_node_put(dev);
        dev = parent;
        parent = get_parent(dev);

        /* If root, we have finished */
        if (parent == NULL) {
            pr_debug("reached root node\n");
            return of_read_number(addr, na);
        }

        /*
         * For indirectIO device which has no ranges property, get
         * the address from reg directly.
         */
        iorange = find_io_range_by_fwnode(&dev->fwnode);
        if (iorange && (iorange->flags != LOGIC_PIO_CPU_MMIO)) {
            u64 result = of_read_number(addr + 1, na - 1);
            pr_debug("indirectIO matched(%pOF) 0x%llx\n",
                 dev, result);
            *host = no_free_ptr(dev);
            return result;
        }

        /* Get new parent bus and counts */
        pbus = of_match_bus(parent);
        pbus->count_cells(dev, &pna, &pns);
        if (!OF_CHECK_COUNTS(pna, pns)) {
            pr_err("Bad cell count for %pOF\n", dev);
            return OF_BAD_ADDR;
        }

        pr_debug("parent bus is %s (na=%d, ns=%d) on %pOF\n",
            pbus->name, pna, pns, parent);

        /* Apply bus translation */
        if (of_translate_one(dev, bus, pbus, addr, na, ns, pna, rprop))
            return OF_BAD_ADDR;

        /* Complete the move up one level */
        na = pna;
        ns = pns;
        bus = pbus;

        of_dump_addr("one level translation:", addr, na);
    }

    unreachable();
}

u64 of_translate_address(struct device_node *dev, const __be32 *in_addr)
{
    struct device_node *host;
    u64 ret;

    ret = __of_translate_address(dev, of_get_parent,
                     in_addr, "ranges", &host);
    if (host) {
        of_node_put(host);
        return OF_BAD_ADDR;
    }

    return ret;
}

#ifdef CONFIG_HAS_DMA
struct device_node *__of_get_dma_parent(const struct device_node *np)
{
    struct of_phandle_args args;
    int ret, index;

    index = of_property_match_string(np, "interconnect-names", "dma-mem");
    if (index < 0)
        return of_get_parent(np);

    ret = of_parse_phandle_with_args(np, "interconnects",
                     "#interconnect-cells",
                     index, &args);
    if (ret < 0)
        return of_get_parent(np);

    return args.np;
}

static int parser_init(struct of_pci_range_parser *parser,
            struct device_node *node, const char *name)
{
    int rlen;

    parser->node = node;
    parser->pna = of_n_addr_cells(node);
    parser->na = of_bus_n_addr_cells(node);
    parser->ns = of_bus_n_size_cells(node);
    parser->dma = !strcmp(name, "dma-ranges");
    parser->bus = of_match_bus(node);

    parser->range = of_get_property(node, name, &rlen);
    if (parser->range == NULL)
        return -ENOENT;

    parser->end = parser->range + rlen / sizeof(__be32);

    return 0;
}

struct of_pci_range *of_pci_range_parser_one(struct of_pci_range_parser *parser,
                        struct of_pci_range *range)
{
    int na = parser->na;
    int ns = parser->ns;
    int np = parser->pna + na + ns;
    int busflag_na = parser->bus->flag_cells;

    if (!range)
        return NULL;

    if (!parser->range || parser->range + np > parser->end)
        return NULL;

    PANIC("");
}

int of_pci_dma_range_parser_init(struct of_pci_range_parser *parser,
                struct device_node *node)
{
    return parser_init(parser, node, "dma-ranges");
}
#define of_dma_range_parser_init of_pci_dma_range_parser_init

static struct device_node *of_get_next_dma_parent(struct device_node *np)
{
    struct device_node *parent;

    parent = __of_get_dma_parent(np);
    of_node_put(np);

    return parent;
}

/**
 * of_dma_get_range - Get DMA range info and put it into a map array
 * @np:     device node to get DMA range info
 * @map:    dma range structure to return
 *
 * Look in bottom up direction for the first "dma-ranges" property
 * and parse it.  Put the information into a DMA offset map array.
 *
 * dma-ranges format:
 *  DMA addr (dma_addr) : naddr cells
 *  CPU addr (phys_addr_t)  : pna cells
 *  size            : nsize cells
 *
 * It returns -ENODEV if "dma-ranges" property was not found for this
 * device in the DT.
 */
int of_dma_get_range(struct device_node *np, const struct bus_dma_region **map)
{
    struct device_node *node __free(device_node) = of_node_get(np);
    const __be32 *ranges = NULL;
    bool found_dma_ranges = false;
    struct of_range_parser parser;
    struct of_range range;
    struct bus_dma_region *r;
    int len, num_ranges = 0;

    while (node) {
        ranges = of_get_property(node, "dma-ranges", &len);

        /* Ignore empty ranges, they imply no translation required */
        if (ranges && len > 0)
            break;

        /* Once we find 'dma-ranges', then a missing one is an error */
        if (found_dma_ranges && !ranges)
            return -ENODEV;

        found_dma_ranges = true;

        node = of_get_next_dma_parent(node);
    }

    if (!node || !ranges) {
        pr_debug("no dma-ranges found for node(%pOF)\n", np);
        return -ENODEV;
    }
    of_dma_range_parser_init(&parser, node);
    for_each_of_range(&parser, &range) {
        if (range.cpu_addr == OF_BAD_ADDR) {
            pr_err("translation of DMA address(%llx) to CPU address failed node(%pOF)\n",
                   range.bus_addr, node);
            continue;
        }
        num_ranges++;
    }

    if (!num_ranges)
        return -EINVAL;

    r = kcalloc(num_ranges + 1, sizeof(*r), GFP_KERNEL);
    if (!r)
        return -ENOMEM;

    PANIC("");
}
#endif

/**
 * of_dma_is_coherent - Check if device is coherent
 * @np: device node
 *
 * It returns true if "dma-coherent" property was found
 * for this device in the DT, or if DMA is coherent by
 * default for OF devices on the current platform and no
 * "dma-noncoherent" property was found for this device.
 */
bool of_dma_is_coherent(struct device_node *np)
{
    struct device_node *node __free(device_node) = of_node_get(np);

    while (node) {
        if (of_property_read_bool(node, "dma-coherent"))
            return true;

        if (of_property_read_bool(node, "dma-noncoherent"))
            return false;

        node = of_get_next_dma_parent(node);
    }
    return dma_default_coherent;
}
