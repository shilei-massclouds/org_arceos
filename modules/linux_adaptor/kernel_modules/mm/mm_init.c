#include <linux/mm.h>

#include "../adaptor.h"

/*
 * mem_map
 */

struct page *mem_map;
unsigned long pfn_base;
unsigned long max_mapnr;

int init_mem_map(unsigned long pa_start, unsigned long pa_end)
{
    if (pa_start >= pa_end) {
        PANIC("bad range for 'mem_map'!");
    }
    pa_start >>= PAGE_SHIFT;
    pa_end >>= PAGE_SHIFT;
#if 0

    unsigned int size = (pa_end - pa_start) * sizeof(struct page);
    mem_map = alloc_pages_exact(PAGE_ALIGN(size), 0);
    pfn_base = pa_start;
    max_mapnr = pa_end - pa_start;
#endif
    pr_info("%s: pfn_base %lx, max_mapnr %lx", __func__, pfn_base, max_mapnr);
    return 0;
}
