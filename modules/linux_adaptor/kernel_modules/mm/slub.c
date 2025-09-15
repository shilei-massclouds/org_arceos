#include <linux/mm.h>
#include <linux/swap.h> /* mm_account_reclaimed_pages() */
#include <linux/module.h>
#include <linux/bit_spinlock.h>
#include <linux/interrupt.h>
#include <linux/swab.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include "slab.h"
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kasan.h>
#include <linux/kmsan.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/mempolicy.h>
#include <linux/ctype.h>
#include <linux/stackdepot.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#include <linux/kfence.h>
#include <linux/memory.h>
#include <linux/math64.h>
#include <linux/fault-inject.h>
#include <linux/kmemleak.h>
#include <linux/stacktrace.h>
#include <linux/prefetch.h>
#include <linux/memcontrol.h>
#include <linux/random.h>
#include <kunit/test.h>
#include <kunit/test-bug.h>
#include <linux/sort.h>

#include <linux/debugfs.h>
#include <trace/events/kmem.h>

#include "internal.h"
#include "../adaptor.h"

#ifndef CONFIG_SLUB_TINY
#define __fastpath_inline __always_inline
#else
#define __fastpath_inline
#endif

static void *cl_kmalloc(size_t size, gfp_t flags)
{
    unsigned char *ret = cl_rust_alloc(size, 8);
    if (flags & __GFP_ZERO) {
        memset(ret, 0, size);
    }
    return (void *) ret;
}

void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t gfpflags, size_t size)
{
    return cl_kmalloc(size, gfpflags);
}

void *__kmalloc_noprof(size_t size, gfp_t flags)
{
    return cl_kmalloc(size, flags);
}

void *__kmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
{
    return cl_kmalloc(size, flags);
}

void *__kmalloc_node_track_caller_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags,
                     int node, unsigned long caller)
{
    return cl_kmalloc(size, flags);
}

void *__kmalloc_cache_node_noprof(struct kmem_cache *s, gfp_t gfpflags,
                  int node, size_t size)
{
    return cl_kmalloc(size, gfpflags);
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
    if (s->ctor && (gfpflags & __GFP_ZERO)) {
        PANIC("kmem_cache ctor conflicts with GFP_ZERO.");
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
    if (gfpflags & __GFP_ZERO) {
        memset(ret, 0, s->size);
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
    pr_notice("%s: ...", __func__);
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
    pr_notice("%s: No impl.", __func__);
}

void skip_orig_size_check(struct kmem_cache *s, const void *object)
{
    pr_err("%s: No impl.", __func__);
    //set_orig_size(s, (void *)object, s->object_size);
}

static __fastpath_inline
struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s, gfp_t flags)
{
    flags &= gfp_allowed_mask;

    might_alloc(flags);

    if (unlikely(should_failslab(s, flags)))
        return NULL;

    return s;
}

static __fastpath_inline
bool slab_post_alloc_hook(struct kmem_cache *s, struct list_lru *lru,
              gfp_t flags, size_t size, void **p, bool init,
              unsigned int orig_size)
{
    pr_notice("%s: No impl.", __func__);
    return true;
}

static inline
int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
                void **p)
{
    int i;
    for (i = 0; i < size; i++) {
        //p[i] = cl_kmalloc(s->object_size, flags);
        p[i] = kmem_cache_alloc_noprof(s, flags);
        printk("%s: [%d]\n", __func__, i);
    }
    return i;
}

/* Note that interrupts must be enabled when calling this function. */
int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
                 void **p)
{
    int i;

    if (!size)
        return 0;

    s = slab_pre_alloc_hook(s, flags);
    if (unlikely(!s))
        return 0;

    i = __kmem_cache_alloc_bulk(s, flags, size, p);
    if (unlikely(i == 0))
        return 0;

    /*
     * memcg and kmem_cache debug support and memory initialization.
     * Done outside of the IRQ disabled fastpath loop.
     */
    if (unlikely(!slab_post_alloc_hook(s, NULL, flags, size, p,
            slab_want_init_on_alloc(flags, s), s->object_size))) {
        return 0;
    }
    return i;
}
