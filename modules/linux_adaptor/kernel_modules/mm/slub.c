#include <linux/mm.h>
#include <linux/slab.h>

#include "slab.h"
#include "../adaptor.h"

void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t gfpflags, size_t size)
{
    return cl_rust_alloc(size, 8);
}

void *__kmalloc_noprof(size_t size, gfp_t flags)
{
    return cl_rust_alloc(size, 8);
}

void *__kmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
{
    return cl_rust_alloc(size, 8);
}

void *__kmalloc_node_track_caller_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags,
                     int node, unsigned long caller)
{
    return cl_rust_alloc(size, 8);
}

void *__kmalloc_cache_node_noprof(struct kmem_cache *s, gfp_t gfpflags,
                  int node, size_t size)
{
    return cl_rust_alloc(size, 8);
}

void *kmem_cache_alloc_noprof(struct kmem_cache *s, gfp_t gfpflags)
{
    if (!s) {
        PANIC("Bad kmem_cache");
    }
    printk("%s: object_size(%u, %u)\n", __func__, s->object_size, s->size);
    return cl_rust_alloc(s->size, s->align);
}
