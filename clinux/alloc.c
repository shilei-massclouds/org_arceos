#include <linux/types.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include "booter.h"

struct kmem_cache {
	unsigned int size;	/* The size of an object including metadata */
	unsigned int align;		/* Alignment */
};

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

void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
{
    if (s->size == 0) {
        booter_panic("bad kmem cache alloc!");
    }
    return kmalloc(s->size, gfpflags);
}
