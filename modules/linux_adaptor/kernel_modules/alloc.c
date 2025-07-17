#include <linux/types.h>
#include <linux/printk.h>
#include <linux/device.h>
#include <linux/mm.h>
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

void *kvmalloc_node(size_t size, gfp_t flags, int node)
{
    return __kmalloc(size, flags);
}

void kfree(const void *x)
{
    cl_rust_dealloc(x);
}

void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
{
    return cl_alloc_pages(size, PAGE_SIZE);
}

/*
 * This is the 'heart' of the zoned buddy allocator.
 */
struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
                       int preferred_nid, nodemask_t *nodemask)
{
    struct page * page = virt_to_page(cl_alloc_pages(PAGE_SIZE << order, PAGE_SIZE));
    set_page_count(page, 1);
    return page;
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
    void (*ctor)(void *);
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
    cache->ctor = ctor;
    return cache;
}

struct kmem_cache *
kmem_cache_create(const char *name, unsigned int size, unsigned int align,
        slab_flags_t flags, void (*ctor)(void *))
{
    return kmem_cache_create_usercopy(name, size, align, flags, 0, 0,
                      ctor);
}

void kmem_cache_destroy(struct kmem_cache *s)
{
    kfree(s);
}

void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
    kfree(objp);
}

/*
 * mem_map
 */

struct page *mem_map;
unsigned long pfn_base;
unsigned long max_mapnr;

int init_mem_map(unsigned long pa_start, unsigned long pa_end)
{
    if (pa_start >= pa_end) {
        booter_panic("bad range for 'mem_map'!");
    }
    pa_start >>= PAGE_SHIFT;
    pa_end >>= PAGE_SHIFT;

    unsigned int size = (pa_end - pa_start) * sizeof(struct page);
    mem_map = alloc_pages_exact(PAGE_ALIGN(size), 0);
    pfn_base = pa_start;
    max_mapnr = pa_end - pa_start;
    log_debug("%s: pfn_base %lx, max_mapnr %lx", __func__, pfn_base, max_mapnr);
    return 0;
}
