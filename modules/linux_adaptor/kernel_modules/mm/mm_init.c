#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/export.h>
#include <linux/memory.h>
#include <linux/notifier.h>
#include <linux/sched.h>
#include <linux/mman.h>
#include <linux/memblock.h>
#include <linux/page-isolation.h>
#include <linux/padata.h>
#include <linux/nmi.h>
#include <linux/buffer_head.h>
#include <linux/kmemleak.h>
#include <linux/kfence.h>
#include <linux/page_ext.h>
#include <linux/pti.h>
#include <linux/pgtable.h>
#include <linux/stackdepot.h>
#include <linux/swap.h>
#include <linux/cma.h>
#include <linux/crash_dump.h>
#include <linux/execmem.h>
#include <linux/vmstat.h>
#include "internal.h"
#include "slab.h"
#include "shuffle.h"

#include <asm/setup.h>

#include "../adaptor.h"

/*
 * Adaptive scale is meant to reduce sizes of hash tables on large memory
 * machines. As memory size is increased the scale is also increased but at
 * slower pace.  Starting from ADAPT_SCALE_BASE (64G), every time memory
 * quadruples the scale is increased by one, which means the size of hash table
 * only doubles, instead of quadrupling as well.
 * Because 32-bit systems cannot have large physical memory, where this scaling
 * makes sense, it is disabled on such platforms.
 */
#if __BITS_PER_LONG > 32
#define ADAPT_SCALE_BASE    (64ul << 30)
#define ADAPT_SCALE_SHIFT   2
#define ADAPT_SCALE_NPAGES  (ADAPT_SCALE_BASE >> PAGE_SHIFT)
#endif

struct kernel_mapping kernel_map __ro_after_init;

/*
 * mem_map
 */

struct page *mem_map;
unsigned long pfn_base;
unsigned long max_mapnr;
phys_addr_t phys_ram_base __ro_after_init;

static unsigned long nr_kernel_pages __initdata;
static unsigned long nr_all_pages __initdata;

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
    nr_kernel_pages = max_mapnr;
    nr_all_pages = max_mapnr;
    pr_info("%s: pfn_base (0x%lx), max_mapnr (%lu)", __func__, pfn_base, max_mapnr);
    return 0;
}

void setup_paging(unsigned long va_pa_offset)
{
    printk("%s: set va_pa_offset(0x%lx)\n", __func__, va_pa_offset);
    kernel_map.page_offset = va_pa_offset;
    kernel_map.va_pa_offset = va_pa_offset;
}

/*
 * allocate a large system hash table from bootmem
 * - it is assumed that the hash table must contain an exact power-of-2
 *   quantity of entries
 * - limit is the number of hash buckets, not the total allocation size
 */
void *__init alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit)
{
	unsigned long long max = high_limit;
	unsigned long log2qty, size;
	void *table;
	gfp_t gfp_flags;
	bool virt;
	bool huge;

	/* allow the kernel cmdline to have a say */
	if (!numentries) {
		/* round applicable memory size up to nearest megabyte */
		numentries = nr_kernel_pages;

		/* It isn't necessary when PAGE_SIZE >= 1MB */
		if (PAGE_SIZE < SZ_1M)
			numentries = round_up(numentries, SZ_1M / PAGE_SIZE);

#if __BITS_PER_LONG > 32
		if (!high_limit) {
			unsigned long adapt;

			for (adapt = ADAPT_SCALE_NPAGES; adapt < numentries;
			     adapt <<= ADAPT_SCALE_SHIFT)
				scale++;
		}
#endif

		/* limit to 1 bucket per 2^scale bytes of low memory */
		if (scale > PAGE_SHIFT)
			numentries >>= (scale - PAGE_SHIFT);
		else
			numentries <<= (PAGE_SHIFT - scale);

		if (unlikely((numentries * bucketsize) < PAGE_SIZE))
			numentries = PAGE_SIZE / bucketsize;
	}
	numentries = roundup_pow_of_two(numentries);

	/* limit allocation size to 1/16 total memory by default */
	if (max == 0) {
		max = ((unsigned long long)nr_all_pages << PAGE_SHIFT) >> 4;
		do_div(max, bucketsize);
	}
	max = min(max, 0x80000000ULL);

	if (numentries < low_limit)
		numentries = low_limit;
	if (numentries > max)
		numentries = max;

	log2qty = ilog2(numentries);

	gfp_flags = (flags & HASH_ZERO) ? GFP_ATOMIC | __GFP_ZERO : GFP_ATOMIC;
	do {
		virt = false;
		size = bucketsize << log2qty;
		if (flags & HASH_EARLY) {
			if (flags & HASH_ZERO)
				table = memblock_alloc(size, SMP_CACHE_BYTES);
			else
				table = memblock_alloc_raw(size,
							   SMP_CACHE_BYTES);
		} else if (get_order(size) > MAX_PAGE_ORDER || hashdist) {
			table = vmalloc_huge(size, gfp_flags);
			virt = true;
			if (table)
				huge = is_vm_area_hugepages(table);
		} else {
			/*
			 * If bucketsize is not a power-of-two, we may free
			 * some pages at the end of hash table which
			 * alloc_pages_exact() automatically does
			 */
			table = alloc_pages_exact(size, gfp_flags);
			kmemleak_alloc(table, size, 1, gfp_flags);
		}
	} while (!table && size > PAGE_SIZE && --log2qty);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	pr_info("%s hash table entries: %ld (order: %d, %lu bytes, %s)\n",
		tablename, 1UL << log2qty, ilog2(size) - PAGE_SHIFT, size,
		virt ? (huge ? "vmalloc hugepage" : "vmalloc") : "linear");

	if (_hash_shift)
		*_hash_shift = log2qty;
	if (_hash_mask)
		*_hash_mask = (1 << log2qty) - 1;

	return table;
}
