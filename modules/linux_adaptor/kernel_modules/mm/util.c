#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/hugetlb.h>

#include "../adaptor.h"

/**
 * kfree_const - conditionally free memory
 * @x: pointer to the memory
 *
 * Function calls kfree only if @x is not in .rodata section.
 */
void kfree_const(const void *x)
{
    if (!is_kernel_rodata((unsigned long)x))
        kfree(x);
}

/**
 * kstrdup_const - conditionally duplicate an existing const string
 * @s: the string to duplicate
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 *
 * Note: Strings allocated by kstrdup_const should be freed by kfree_const and
 * must not be passed to krealloc().
 *
 * Return: source string if it is in .rodata section otherwise
 * fallback to kstrdup.
 */
const char *kstrdup_const(const char *s, gfp_t gfp)
{
    if (is_kernel_rodata((unsigned long)s))
        return s;

    return kstrdup(s, gfp);
}

/**
 * kstrdup - allocate space for and copy an existing string
 * @s: the string to duplicate
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 *
 * Return: newly allocated copy of @s or %NULL in case of error
 */
noinline
char *kstrdup(const char *s, gfp_t gfp)
{
    size_t len;
    char *buf;

    if (!s)
        return NULL;

    len = strlen(s) + 1;
    buf = kmalloc_track_caller(len, gfp);
    if (buf)
        memcpy(buf, s, len);
    return buf;
}

static gfp_t kmalloc_gfp_adjust(gfp_t flags, size_t size)
{
    /*
     * We want to attempt a large physically contiguous block first because
     * it is less likely to fragment multiple larger blocks and therefore
     * contribute to a long term fragmentation less than vmalloc fallback.
     * However make sure that larger requests are not too disruptive - no
     * OOM killer and no allocation failure warnings as we have a fallback.
     */
    if (size > PAGE_SIZE) {
        flags |= __GFP_NOWARN;

        if (!(flags & __GFP_RETRY_MAYFAIL))
            flags |= __GFP_NORETRY;

        /* nofail semantic is implemented by the vmalloc fallback */
        flags &= ~__GFP_NOFAIL;
    }

    return flags;
}

/**
 * __kvmalloc_node - attempt to allocate physically contiguous memory, but upon
 * failure, fall back to non-contiguous (vmalloc) allocation.
 * @size: size of the request.
 * @b: which set of kmalloc buckets to allocate from.
 * @flags: gfp mask for the allocation - must be compatible (superset) with GFP_KERNEL.
 * @node: numa node to allocate from
 *
 * Uses kmalloc to get the memory but if the allocation fails then falls back
 * to the vmalloc allocator. Use kvfree for freeing the memory.
 *
 * GFP_NOWAIT and GFP_ATOMIC are not supported, neither is the __GFP_NORETRY modifier.
 * __GFP_RETRY_MAYFAIL is supported, and it should be used only if kmalloc is
 * preferable to the vmalloc fallback, due to visible performance drawbacks.
 *
 * Return: pointer to the allocated memory of %NULL in case of failure
 */
void *__kvmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
{
    void *ret;

    /*
     * It doesn't really make sense to fallback to vmalloc for sub page
     * requests
     */
    ret = __kmalloc_node_noprof(PASS_BUCKET_PARAMS(size, b),
                    kmalloc_gfp_adjust(flags, size),
                    node);
    if (ret || size <= PAGE_SIZE)
        return ret;

#if 0
    /* non-sleeping allocations are not supported by vmalloc */
    if (!gfpflags_allow_blocking(flags))
        return NULL;

    /* Don't even allow crazy sizes */
    if (unlikely(size > INT_MAX)) {
        WARN_ON_ONCE(!(flags & __GFP_NOWARN));
        return NULL;
    }

    /*
     * kvmalloc() can always use VM_ALLOW_HUGE_VMAP,
     * since the callers already cannot assume anything
     * about the resulting pointer, and cannot play
     * protection games.
     */
    return __vmalloc_node_range_noprof(size, 1, VMALLOC_START, VMALLOC_END,
            flags, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
            node, __builtin_return_address(0));
#endif
    PANIC("");
}

/**
 * kmemdup_nul - Create a NUL-terminated string from unterminated data
 * @s: The data to stringify
 * @len: The size of the data
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 *
 * Return: newly allocated copy of @s with NUL-termination or %NULL in
 * case of error
 */
char *kmemdup_nul(const char *s, size_t len, gfp_t gfp)
{
    char *buf;

    if (!s)
        return NULL;

    buf = kmalloc_track_caller(len + 1, gfp);
    if (buf) {
        memcpy(buf, s, len);
        buf[len] = '\0';
    }
    return buf;
}
