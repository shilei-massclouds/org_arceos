#include <linux/types.h>
#include <linux/printk.h>
#include <linux/device.h>
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

/*
 * kmem cache
 */

struct kmem_cache {
	unsigned int size;  /* The size of an object including metadata */
	unsigned int align; /* Alignment */
};

struct kmem_cache *
kmem_cache_create_usercopy(const char *name,
          unsigned int size, unsigned int align,
          slab_flags_t flags,
          unsigned int useroffset, unsigned int usersize,
          void (*ctor)(void *))
{
    struct kmem_cache *cache = kmalloc(sizeof(struct kmem_cache), 0);
    memset(cache, 0, sizeof(struct kmem_cache));
    cache->size = size;
    cache->align = align;
    return cache;
}
