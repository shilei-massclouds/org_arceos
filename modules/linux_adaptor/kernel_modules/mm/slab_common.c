#include <linux/slab.h>

#include "slab.h"
#include "../adaptor.h"

enum slab_state slab_state;

kmem_buckets kmalloc_caches[NR_KMALLOC_TYPES] __ro_after_init =
{ /* initialization for https://llvm.org/pr42570 */ };

/**
 * __kmem_cache_create_args - Create a kmem cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @object_size: The size of objects to be created in this cache.
 * @args: Additional arguments for the cache creation (see
 *        &struct kmem_cache_args).
 * @flags: See %SLAB_* flags for an explanation of individual @flags.
 *
 * Not to be called directly, use the kmem_cache_create() wrapper with the same
 * parameters.
 *
 * Context: Cannot be called within a interrupt, but can be interrupted.
 *
 * Return: a pointer to the cache on success, NULL on failure.
 */
struct kmem_cache *__kmem_cache_create_args(const char *name,
                        unsigned int object_size,
                        struct kmem_cache_args *args,
                        slab_flags_t flags)
{
    pr_err("%s: No impl. object_size(%u) align(%u)\n", __func__, object_size, args->align);

    struct kmem_cache *cache = kmalloc(sizeof(struct kmem_cache), 0);
    memset(cache, 0, sizeof(struct kmem_cache));
    cache->object_size = object_size;
    cache->size = object_size;
    cache->align = args->align;
    cache->ctor = args->ctor;
    return cache;
}

size_t kmalloc_size_roundup(size_t size)
{
    if (size && size <= KMALLOC_MAX_CACHE_SIZE) {
        /*
         * The flags don't matter since size_index is common to all.
         * Neither does the caller for just getting ->object_size.
         */
#if 0
        return kmalloc_slab(size, NULL, GFP_KERNEL, 0)->object_size;
#else
        size_t ret = ALIGN(size, 8);
        pr_err("%s: No impl for kmalloc_slab. size(%u -> %u)",
               __func__, size, ret);
        return ret;
#endif
    }

    /* Above the smaller buckets, size is a multiple of page size. */
    if (size && size <= KMALLOC_MAX_SIZE)
        return PAGE_SIZE << get_order(size);

    /*
     * Return 'size' for 0 - kmalloc() returns ZERO_SIZE_PTR
     * and very large size - kmalloc() may fail.
     */
    return size;
}

bool slab_is_available(void)
{
    pr_err("%s: No impl.", __func__);
    return true;
    //return slab_state >= UP;
}

/*
 * Determine the size of a slab object
 */
unsigned int kmem_cache_size(struct kmem_cache *s)
{
    return s->object_size;
}
