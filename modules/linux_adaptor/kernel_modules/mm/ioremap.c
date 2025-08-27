#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/ioremap.h>

#include "../adaptor.h"

void __iomem *generic_ioremap_prot(phys_addr_t phys_addr, size_t size,
                   pgprot_t prot)
{
    unsigned long offset, vaddr;
    phys_addr_t last_addr;
    struct vm_struct *area;

    /* An early platform driver might end up here */
    if (WARN_ON_ONCE(!slab_is_available()))
        return NULL;

    /* Disallow wrap-around or zero size */
    last_addr = phys_addr + size - 1;
    if (!size || last_addr < phys_addr)
        return NULL;

    /* Page-align mappings */
    offset = phys_addr & (~PAGE_MASK);
    phys_addr -= offset;
    size = PAGE_ALIGN(size + offset);

    vaddr = phys_addr + kernel_map.va_pa_offset;
    pr_info("%s: VA: %lx -> PA: %lx\n", __func__, vaddr, phys_addr);

    pr_info("%s: Use linear mapping in ArceOS to handle ioremap.\n", __func__);
    /* Use linear mapping in ArceOS to handle ioremap. */
#if 0
    area = __get_vm_area_caller(size, VM_IOREMAP, IOREMAP_START,
                    IOREMAP_END, __builtin_return_address(0));
    if (!area)
        return NULL;
    vaddr = (unsigned long)area->addr;
    area->phys_addr = phys_addr;

    if (ioremap_page_range(vaddr, vaddr + size, phys_addr, prot)) {
        free_vm_area(area);
        return NULL;
    }
#endif

    return (void __iomem *)(vaddr + offset);
}

#ifndef ioremap_prot
void __iomem *ioremap_prot(phys_addr_t phys_addr, size_t size,
               unsigned long prot)
{
    return generic_ioremap_prot(phys_addr, size, __pgprot(prot));
}
EXPORT_SYMBOL(ioremap_prot);
#endif
