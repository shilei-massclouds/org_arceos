#include <linux/slab.h>

#include "../adaptor.h"

void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t gfpflags, size_t size)
{
    return cl_rust_alloc(size, 8);
}
