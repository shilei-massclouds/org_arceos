#include <linux/acpi.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/sched.h>
#include <linux/console.h>
#include <linux/of_fdt.h>
#include <linux/sched/task.h>
#include <linux/smp.h>
//#include <linux/efi.h>
#include <linux/crash_dump.h>
#include <linux/panic_notifier.h>

#include <asm/acpi.h>
#include <asm/alternative.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/early_ioremap.h>
#include <asm/pgtable.h>
#include <asm/setup.h>
#include <asm/set_memory.h>
#include <asm/sections.h>
#include <asm/sbi.h>
#include <asm/tlbflush.h>
#include <asm/thread_info.h>
#include <asm/kasan.h>
//#include <asm/efi.h>

//#include "head.h"
#include "adaptor.h"

unsigned long boot_cpu_hartid;

/*
 * Calculate the size of the zone->blockflags rounded to an unsigned long
 * Start by making sure zonesize is a multiple of pageblock_order by rounding
 * up. Then use 1 NR_PAGEBLOCK_BITS worth of bits per pageblock, finally
 * round what is now in bits to nearest long in bits, then return it in
 * bytes.
 */
static unsigned long __init usemap_size(unsigned long zone_start_pfn, unsigned long zonesize)
{
    unsigned long usemapsize;

    zonesize += zone_start_pfn & (pageblock_nr_pages-1);
    usemapsize = roundup(zonesize, pageblock_nr_pages);
    usemapsize = usemapsize >> pageblock_order;
    usemapsize *= NR_PAGEBLOCK_BITS;
    usemapsize = roundup(usemapsize, BITS_PER_LONG);

    return usemapsize / BITS_PER_BYTE;
}

static void __ref setup_usemap(struct zone *zone)
{
    unsigned long usemapsize = usemap_size(zone->zone_start_pfn,
                           zone->spanned_pages);
    zone->pageblock_flags = NULL;
    if (usemapsize) {
        printk("%s: usemapsize(%lx)\n", __func__, usemapsize);
        zone->pageblock_flags =
            memblock_alloc_node(usemapsize, SMP_CACHE_BYTES,
                        zone_to_nid(zone));
        if (!zone->pageblock_flags)
            panic("Failed to allocate %ld bytes for zone %s pageblock flags on node %d\n",
                  usemapsize, zone->name, zone_to_nid(zone));
    }
}

static void __init parse_dtb(void)
{
    /* Early scan of device tree from init memory */
    if (early_init_dt_scan(dtb_early_va, dtb_early_pa)) {
        const char *name = of_flat_dt_get_machine_name();

        if (name) {
            pr_info("Machine model: %s\n", name);
            dump_stack_set_arch_desc("%s (DT)", name);
        }
    } else {
        pr_err("No DTB passed to the kernel\n");
    }
}

void __init setup_arch(char **cmdline_p)
{
    parse_dtb();
    /*
    paging_init();

    // In misc_mem_init()
    int nid = 0;
    pg_data_t *pgdat = NODE_DATA(nid);
    lruvec_init(&pgdat->__lruvec);

    struct zone *zone = pgdat->node_zones + 0;
    zone->zone_start_pfn = min_low_pfn;
    zone->spanned_pages = max_low_pfn - min_low_pfn;
    setup_usemap(zone);
    */
    PANIC("Reach Here!");
}
