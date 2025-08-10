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

void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t gfpflags, int node)
{
    return kmem_cache_alloc_noprof(s, gfpflags);
}

void *kmem_cache_alloc_noprof(struct kmem_cache *s, gfp_t gfpflags)
{
    if (!s) {
        PANIC("Bad kmem_cache");
    }
    pr_debug("%s: object_size(%u, %u) align(%u)",
             __func__, s->object_size, s->size, s->align);

    int align = s->align;
    if (align == 0) {
        align = 8;
    }
    void *ret = cl_rust_alloc(s->size, align);
    if (s->ctor) {
        s->ctor(ret);
    }
    return ret;
}

void *kmem_cache_alloc_lru_noprof(struct kmem_cache *s, struct list_lru *lru,
               gfp_t gfpflags)
{
    return kmem_cache_alloc_noprof(s, gfpflags);
}

/**
 * kfree - free previously allocated memory
 * @object: pointer returned by kmalloc() or kmem_cache_alloc()
 *
 * If @object is NULL, no operation is performed.
 */
void kfree(const void *object)
{
    pr_err("%s: ...", __func__);
    cl_rust_dealloc(object);
}

/**
 * kmem_cache_free - Deallocate an object
 * @s: The cache the allocation was from.
 * @x: The previously allocated object.
 *
 * Free an object which was previously allocated from this
 * cache.
 */
void kmem_cache_free(struct kmem_cache *s, void *x)
{
#if 0
    s = cache_from_obj(s, x);
    if (!s)
        return;
    trace_kmem_cache_free(_RET_IP_, x, s);
    slab_free(s, virt_to_slab(x), x, _RET_IP_);
#endif
    pr_err("%s: No impl.", __func__);
}
