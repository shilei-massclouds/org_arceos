#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/poison.h>
#include <linux/pfn.h>
#include <linux/debugfs.h>
#include <linux/kmemleak.h>
#include <linux/seq_file.h>
#include <linux/memblock.h>

#include <asm/sections.h>
#include <linux/io.h>

#include "internal.h"
#include "adaptor.h"

struct pglist_data __refdata contig_page_data;

unsigned long max_low_pfn;
unsigned long min_low_pfn;
unsigned long max_pfn;

/**
 * memblock_alloc_try_nid - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *    is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *        is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *        allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. This function zeroes the allocated memory.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
void * __init memblock_alloc_try_nid(
            phys_addr_t size, phys_addr_t align,
            phys_addr_t min_addr, phys_addr_t max_addr,
            int nid)
{
    void *ret;
    if (align == 0) {
        align = 8;
    }
    ret = cl_rust_alloc(size, align);
    if (ret) {
        memset(ret, 0, size);
    }
    return ret;
}

/**
 * memblock_free - free boot memory allocation
 * @ptr: starting address of the  boot memory allocation
 * @size: size of the boot memory block in bytes
 *
 * Free boot memory block previously allocated by memblock_alloc_xx() API.
 * The freeing memory will not be released to the buddy allocator.
 */
void __init_memblock memblock_free(void *ptr, size_t size)
{
    if (ptr)
        memblock_phys_free(__pa(ptr), size);
}

/**
 * memblock_phys_free - free boot memory block
 * @base: phys starting address of the  boot memory block
 * @size: size of the boot memory block in bytes
 *
 * Free boot memory block previously allocated by memblock_phys_alloc_xx() API.
 * The freeing memory will not be released to the buddy allocator.
 */
int __init_memblock memblock_phys_free(phys_addr_t base, phys_addr_t size)
{
#if 0
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
             &base, &end, (void *)_RET_IP_);

    kmemleak_free_part_phys(base, size);
    return memblock_remove_range(&memblock.reserved, base, size);
#endif
    cl_rust_dealloc(base);
    return 0;
}
