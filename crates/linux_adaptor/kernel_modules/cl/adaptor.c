#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "adaptor.h"

unsigned long linux_virt_to_phys(unsigned long va)
{
    return __pa(va);
}

unsigned long linux_phys_to_virt(unsigned long pa)
{
    return (unsigned long) __va(pa);
}

void *linux_kmalloc_kernel(size_t size, unsigned int align)
{
    void *ret = kmalloc(size, GFP_KERNEL);
    if (ret == NULL) {
        /* size is too large, try to use vmalloc */
        ret = vmalloc(size);
    }
    CL_ASSERT(IS_ALIGNED((unsigned long)ret, align),
              "kmalloc error: NOT aligned");
    return ret;
}
