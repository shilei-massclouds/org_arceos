#include <linux/slab.h>

#include "slab.h"

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
    return cache;
}
