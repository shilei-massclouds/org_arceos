#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/backing-dev.h>
#include <linux/compiler.h>
#include <linux/mount.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/audit.h>
#include <linux/printk.h>

#include <linux/uaccess.h>
#include <linux/uio.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include "internal.h"
#include "../adaptor.h"

/**
 * vmalloc - allocate virtually contiguous memory
 * @size:    allocation size
 *
 * Allocate enough pages to cover @size from the page level
 * allocator and map them into contiguous kernel virtual space.
 *
 * For tight control over page level allocator and protection flags
 * use __vmalloc() instead.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *vmalloc_noprof(unsigned long size)
{
    return __kmalloc_noprof(size, 0);
#if 0
    return __vmalloc_node_noprof(size, 1, GFP_KERNEL, NUMA_NO_NODE,
                __builtin_return_address(0));
#endif
}

extern void *
cl_vmap_range(unsigned long addr, phys_addr_t phys, unsigned long size, pgprot_t prot);

int vmap_page_range(unsigned long addr, unsigned long end,
            phys_addr_t phys_addr, pgprot_t prot)
{
    printk("%s: (%lx,%lx) -> %lx [%x]\n", __func__, addr, end, phys_addr, prot);
    return cl_vmap_range(addr, phys_addr, end - addr, prot);
#if 0
    int err;

    err = vmap_range_noflush(addr, end, phys_addr, pgprot_nx(prot),
                 ioremap_max_page_shift);
    flush_cache_vmap(addr, end);
    if (!err)
        err = kmsan_ioremap_page_range(addr, end, phys_addr, prot,
                           ioremap_max_page_shift);
    return err;
#endif
}

bool is_vmalloc_addr(const void *x)
{
    unsigned long addr = (unsigned long)kasan_reset_tag(x);

    return addr >= VMALLOC_START && addr < VMALLOC_END;
}
