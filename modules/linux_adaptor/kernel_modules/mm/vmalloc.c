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
#include "adaptor.h"

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

extern int
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

/**
 * __vmalloc_node_range - allocate virtually contiguous memory
 * @size:         allocation size
 * @align:        desired alignment
 * @start:        vm area range start
 * @end:          vm area range end
 * @gfp_mask:         flags for the page level allocator
 * @prot:         protection mask for the allocated pages
 * @vm_flags:         additional vm area flags (e.g. %VM_NO_GUARD)
 * @node:         node to use for allocation or NUMA_NO_NODE
 * @caller:       caller's return address
 *
 * Allocate enough pages to cover @size from the page level
 * allocator with @gfp_mask flags. Please note that the full set of gfp
 * flags are not supported. GFP_KERNEL, GFP_NOFS and GFP_NOIO are all
 * supported.
 * Zone modifiers are not supported. From the reclaim modifiers
 * __GFP_DIRECT_RECLAIM is required (aka GFP_NOWAIT is not supported)
 * and only __GFP_NOFAIL is supported (i.e. __GFP_NORETRY and
 * __GFP_RETRY_MAYFAIL are not supported).
 *
 * __GFP_NOWARN can be used to suppress failures messages.
 *
 * Map them into contiguous kernel virtual space, using a pagetable
 * protection of @prot.
 *
 * Return: the address of the area or %NULL on failure
 */
void *__vmalloc_node_range_noprof(unsigned long size, unsigned long align,
            unsigned long start, unsigned long end, gfp_t gfp_mask,
            pgprot_t prot, unsigned long vm_flags, int node,
            const void *caller)
{
    pr_err("%s: NOTICE!!! implemente it! size(%lx) align(%lx)\n", __func__, size, align);
    if (!IS_ALIGNED(size, PAGE_SIZE)) {
        PANIC("size is NOT aligned to PAGE_SIZE!");
    }
    return cl_alloc_pages(size, PAGE_SIZE);
}

/**
 * __vmalloc_node - allocate virtually contiguous memory
 * @size:       allocation size
 * @align:      desired alignment
 * @gfp_mask:       flags for the page level allocator
 * @node:       node to use for allocation or NUMA_NO_NODE
 * @caller:     caller's return address
 *
 * Allocate enough pages to cover @size from the page level allocator with
 * @gfp_mask flags.  Map them into contiguous kernel virtual space.
 *
 * Reclaim modifiers in @gfp_mask - __GFP_NORETRY, __GFP_RETRY_MAYFAIL
 * and __GFP_NOFAIL are not supported
 *
 * Any use of gfp flags outside of GFP_KERNEL should be consulted
 * with mm people.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *__vmalloc_node_noprof(unsigned long size, unsigned long align,
                gfp_t gfp_mask, int node, const void *caller)
{
    return __vmalloc_node_range_noprof(size, align, VMALLOC_START, VMALLOC_END,
                gfp_mask, PAGE_KERNEL, 0, node, caller);
}

/**
 * vzalloc - allocate virtually contiguous memory with zero fill
 * @size:    allocation size
 *
 * Allocate enough pages to cover @size from the page level
 * allocator and map them into contiguous kernel virtual space.
 * The memory allocated is set to zero.
 *
 * For tight control over page level allocator and protection flags
 * use __vmalloc() instead.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *vzalloc_noprof(unsigned long size)
{
    return __vmalloc_node_noprof(size, 1, GFP_KERNEL | __GFP_ZERO, NUMA_NO_NODE,
                __builtin_return_address(0));
}

bool is_vmalloc_addr(const void *x)
{
    unsigned long addr = (unsigned long)kasan_reset_tag(x);

    return addr >= VMALLOC_START && addr < VMALLOC_END;
}

/**
 * vunmap - release virtual mapping obtained by vmap()
 * @addr:   memory base address
 *
 * Free the virtually contiguous memory area starting at @addr,
 * which was created from the page array passed to vmap().
 *
 * Must not be called in interrupt context.
 */
void vunmap(const void *addr)
{
    struct vm_struct *vm;

#if 0
    BUG_ON(in_interrupt());
    might_sleep();

    if (!addr)
        return;
    vm = remove_vm_area(addr);
    if (unlikely(!vm)) {
        WARN(1, KERN_ERR "Trying to vunmap() nonexistent vm area (%p)\n",
                addr);
        return;
    }
    kfree(vm);
#endif
    PANIC("");
}

/**
 * vunmap_range - unmap kernel virtual addresses
 * @addr: start of the VM area to unmap
 * @end: end of the VM area to unmap (non-inclusive)
 *
 * Clears any present PTEs in the virtual address range, flushes TLBs and
 * caches. Any subsequent access to the address before it has been re-mapped
 * is a kernel bug.
 */
void vunmap_range(unsigned long addr, unsigned long end)
{
    pr_notice("%s: No impl.\n", __func__);
#if 0
    flush_cache_vunmap(addr, end);
    vunmap_range_noflush(addr, end);
    flush_tlb_kernel_range(addr, end);
#endif
}

/**
 * vfree - Release memory allocated by vmalloc()
 * @addr:  Memory base address
 *
 * Free the virtually continuous memory area starting at @addr, as obtained
 * from one of the vmalloc() family of APIs.  This will usually also free the
 * physical memory underlying the virtual allocation, but that memory is
 * reference counted, so it will not be freed until the last user goes away.
 *
 * If @addr is NULL, no operation is performed.
 *
 * Context:
 * May sleep if called *not* from interrupt context.
 * Must not be called in NMI context (strictly speaking, it could be
 * if we have CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG, but making the calling
 * conventions for vfree() arch-dependent would be a really bad idea).
 */
void vfree(const void *addr)
{
    pr_notice("%s: No impl.\n", __func__);
}
