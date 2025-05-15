#include <linux/types.h>
#include <linux/printk.h>
#include "booter.h"

void* __kmalloc(size_t size, gfp_t flags)
{
    return cl_rust_alloc(size, 8);
}

void *kmalloc(size_t size, gfp_t flags)
{
    return __kmalloc(size, flags);
}

void *kmalloc_node(size_t size, gfp_t flags, int node)
{
    return __kmalloc(size, flags);
}

void kfree(const void *x)
{
    cl_rust_dealloc(x);
}

void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
{
    return cl_alloc_pages(size, 0x1000);
}

void *devm_kmalloc(struct device *dev, size_t size, gfp_t gfp)
{
    printk("devm_kmalloc ..\n");
    return cl_rust_alloc(size, 8);
}
