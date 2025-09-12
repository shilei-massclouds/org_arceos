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
    pr_notice("%s: No impl. object_size(%u) align(%u)\n", __func__, object_size, args->align);

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
        pr_notice("%s: No impl for kmalloc_slab. size(%u -> %u)",
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
    pr_notice("%s: No impl.", __func__);
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

static __always_inline __realloc_size(2) void *
__do_krealloc(const void *p, size_t new_size, gfp_t flags)
{
    void *ret;
    size_t ks;

    /* Check for double-free before calling ksize. */
    if (likely(!ZERO_OR_NULL_PTR(p))) {
        if (!kasan_check_byte(p))
            return NULL;
        ks = ksize(p);
    } else
        ks = 0;

    /* If the object still fits, repoison it precisely. */
    if (ks >= new_size) {
        /* Zero out spare memory. */
        if (want_init_on_alloc(flags)) {
            kasan_disable_current();
            memset(kasan_reset_tag(p) + new_size, 0, ks - new_size);
            kasan_enable_current();
        }

        p = kasan_krealloc((void *)p, new_size, flags);
        return (void *)p;
    }

    ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
    if (ret && p) {
        /* Disable KASAN checks as the object's redzone is accessed. */
        kasan_disable_current();
        memcpy(ret, kasan_reset_tag(p), ks);
        kasan_enable_current();
    }

    return ret;
}

/**
 * krealloc - reallocate memory. The contents will remain unchanged.
 * @p: object to reallocate memory for.
 * @new_size: how many bytes of memory are required.
 * @flags: the type of memory to allocate.
 *
 * If @p is %NULL, krealloc() behaves exactly like kmalloc().  If @new_size
 * is 0 and @p is not a %NULL pointer, the object pointed to is freed.
 *
 * If __GFP_ZERO logic is requested, callers must ensure that, starting with the
 * initial memory allocation, every subsequent call to this API for the same
 * memory allocation is flagged with __GFP_ZERO. Otherwise, it is possible that
 * __GFP_ZERO is not fully honored by this API.
 *
 * This is the case, since krealloc() only knows about the bucket size of an
 * allocation (but not the exact size it was allocated with) and hence
 * implements the following semantics for shrinking and growing buffers with
 * __GFP_ZERO.
 *
 *         new             bucket
 * 0       size             size
 * |--------|----------------|
 * |  keep  |      zero      |
 *
 * In any case, the contents of the object pointed to are preserved up to the
 * lesser of the new and old sizes.
 *
 * Return: pointer to the allocated memory or %NULL in case of error
 */
void *krealloc_noprof(const void *p, size_t new_size, gfp_t flags)
{
    void *ret;

    if (unlikely(!new_size)) {
        kfree(p);
        return ZERO_SIZE_PTR;
    }

    ret = __do_krealloc(p, new_size, flags);
    if (ret && kasan_reset_tag(p) != kasan_reset_tag(ret))
        kfree(p);

    return ret;
}

/**
 * __ksize -- Report full size of underlying allocation
 * @object: pointer to the object
 *
 * This should only be used internally to query the true size of allocations.
 * It is not meant to be a way to discover the usable size of an allocation
 * after the fact. Instead, use kmalloc_size_roundup(). Using memory beyond
 * the originally requested allocation size may trigger KASAN, UBSAN_BOUNDS,
 * and/or FORTIFY_SOURCE.
 *
 * Return: size of the actual memory used by @object in bytes
 */
size_t __ksize(const void *object)
{
    struct folio *folio;

    if (unlikely(object == ZERO_SIZE_PTR))
        return 0;

    folio = virt_to_folio(object);

    if (unlikely(!folio_test_slab(folio))) {
        if (WARN_ON(folio_size(folio) <= KMALLOC_MAX_CACHE_SIZE))
            return 0;
        if (WARN_ON(object != folio_address(folio)))
            return 0;
        return folio_size(folio);
    }

#ifdef CONFIG_SLUB_DEBUG
    skip_orig_size_check(folio_slab(folio)->slab_cache, object);
#endif

    return slab_ksize(folio_slab(folio)->slab_cache);
}

size_t ksize(const void *objp)
{
    /*
     * We need to first check that the pointer to the object is valid.
     * The KASAN report printed from ksize() is more useful, then when
     * it's printed later when the behaviour could be undefined due to
     * a potential use-after-free or double-free.
     *
     * We use kasan_check_byte(), which is supported for the hardware
     * tag-based KASAN mode, unlike kasan_check_read/write().
     *
     * If the pointed to memory is invalid, we return 0 to avoid users of
     * ksize() writing to and potentially corrupting the memory region.
     *
     * We want to perform the check before __ksize(), to avoid potentially
     * crashing in __ksize() due to accessing invalid metadata.
     */
    if (unlikely(ZERO_OR_NULL_PTR(objp)) || !kasan_check_byte(objp))
        return 0;

    return kfence_ksize(objp) ?: __ksize(objp);
}
