#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "adaptor.h"

unsigned long linux_virt_to_phys(unsigned long va)
{
    if (is_vmalloc_addr((void *)va)) {
        struct page *page = vmalloc_to_page(va);
        return page_to_phys(page) + offset_in_page(va);
    }
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
        printk("kmalloc.size: 0x%lx, it's too large, use vmalloc instead.\n", size);
        ret = vmalloc(size);
    }
    CL_ASSERT(IS_ALIGNED((unsigned long)ret, align),
              "kmalloc error: NOT aligned");
    return ret;
}

struct task_struct *linux_current()
{
    return current;
}

unsigned long linux_my_cpu_offset()
{
    return __my_cpu_offset;
}

void set_current_need_resched()
{
    set_tsk_need_resched(current);
}

pid_t linux_kernel_thread(int (*fn)(void *), void *opaque)
{
    return kernel_thread(fn, opaque, NULL, CLONE_FS | CLONE_FILES);
}
