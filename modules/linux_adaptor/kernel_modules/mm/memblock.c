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
#include "../adaptor.h"

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
    if (align == 0) {
        align = 8;
    }
    return cl_rust_alloc(size, align);
}
