#include <linux/mm.h>

#include "../adaptor.h"

struct kernel_mapping kernel_map __ro_after_init;

/*
 * mem_map
 */

struct page *mem_map;
unsigned long pfn_base;
unsigned long max_mapnr;
phys_addr_t phys_ram_base __ro_after_init;

int init_mem_map(unsigned long pa_start, unsigned long pa_end)
{
    if (pa_start >= pa_end) {
        PANIC("bad range for 'mem_map'!");
    }
    phys_ram_base = pa_start;
    pa_start >>= PAGE_SHIFT;
    pa_end >>= PAGE_SHIFT;

    unsigned int size = (pa_end - pa_start) * sizeof(struct page);
    mem_map = alloc_pages_exact(PAGE_ALIGN(size), 0);
    pfn_base = pa_start;
    max_mapnr = pa_end - pa_start;
    pr_info("%s: pfn_base (0x%lx), max_mapnr (%lu)", __func__, pfn_base, max_mapnr);
    return 0;
}

void setup_paging(unsigned long va_pa_offset)
{
    printk("%s: set va_pa_offset(0x%lx)\n", __func__, va_pa_offset);
    kernel_map.page_offset = va_pa_offset;
    kernel_map.va_pa_offset = va_pa_offset;
}
