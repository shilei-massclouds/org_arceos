#include <linux/memblock.h> /* for max_pfn */
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/dma-map-ops.h>
#include <linux/scatterlist.h>
#include <linux/pfn.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include "direct.h"

#include "../adaptor.h"

/*
 * Most architectures use ZONE_DMA for the first 16 Megabytes, but some use
 * it for entirely different regions. In that case the arch code needs to
 * override the variable below for dma-direct to work properly.
 */
u64 zone_dma_limit __ro_after_init = DMA_BIT_MASK(24);

static inline dma_addr_t phys_to_dma_direct(struct device *dev,
        phys_addr_t phys)
{
    if (force_dma_unencrypted(dev))
        return phys_to_dma_unencrypted(dev, phys);
    return phys_to_dma(dev, phys);
}

size_t dma_direct_max_mapping_size(struct device *dev)
{
    /* If SWIOTLB is active, use its maximum mapping size */
    if (is_swiotlb_active(dev) &&
        (dma_addressing_limited(dev) || is_swiotlb_force_bounce(dev)))
        return swiotlb_max_mapping_size(dev);
    return SIZE_MAX;
}

static int dma_set_encrypted(struct device *dev, void *vaddr, size_t size)
{
    int ret;

    if (!force_dma_unencrypted(dev))
        return 0;
    ret = set_memory_encrypted((unsigned long)vaddr, PFN_UP(size));
    if (ret)
        pr_warn_ratelimited("leaking DMA memory that can't be re-encrypted\n");
    return ret;
}

static void __dma_direct_free_pages(struct device *dev, struct page *page,
                    size_t size)
{
    if (swiotlb_free(dev, page, size))
        return;
    dma_free_contiguous(dev, page, size);
}

static void *dma_direct_alloc_no_mapping(struct device *dev, size_t size,
        dma_addr_t *dma_handle, gfp_t gfp)
{
    struct page *page;

#if 0
    page = __dma_direct_alloc_pages(dev, size, gfp & ~__GFP_ZERO, true);
    if (!page)
        return NULL;

    /* remove any dirty cache lines on the kernel alias */
    if (!PageHighMem(page))
        arch_dma_prep_coherent(page, size);

    /* return the page pointer as the opaque cookie */
    *dma_handle = phys_to_dma_direct(dev, page_to_phys(page));
#endif
    PANIC("");
    return page;
}

static gfp_t dma_direct_optimal_gfp_mask(struct device *dev, u64 *phys_limit)
{
    u64 dma_limit = min_not_zero(
        dev->coherent_dma_mask,
        dev->bus_dma_limit);

    /*
     * Optimistically try the zone that the physical address mask falls
     * into first.  If that returns memory that isn't actually addressable
     * we will fallback to the next lower zone and try again.
     *
     * Note that GFP_DMA32 and GFP_DMA are no ops without the corresponding
     * zones.
     */
    *phys_limit = dma_to_phys(dev, dma_limit);
    if (*phys_limit <= zone_dma_limit)
        return GFP_DMA;
    if (*phys_limit <= DMA_BIT_MASK(32))
        return GFP_DMA32;
    return 0;
}

static int dma_set_decrypted(struct device *dev, void *vaddr, size_t size)
{
    if (!force_dma_unencrypted(dev))
        return 0;
    return set_memory_decrypted((unsigned long)vaddr, PFN_UP(size));
}

/*
 * Check if a potentially blocking operations needs to dip into the atomic
 * pools for the given device/gfp.
 */
static bool dma_direct_use_pool(struct device *dev, gfp_t gfp)
{
    return !gfpflags_allow_blocking(gfp) && !is_swiotlb_for_alloc(dev);
}

static void *dma_direct_alloc_from_pool(struct device *dev, size_t size,
        dma_addr_t *dma_handle, gfp_t gfp)
{
    struct page *page;
    u64 phys_limit;
    void *ret;

    if (WARN_ON_ONCE(!IS_ENABLED(CONFIG_DMA_COHERENT_POOL)))
        return NULL;

    gfp |= dma_direct_optimal_gfp_mask(dev, &phys_limit);
    page = dma_alloc_from_pool(dev, size, &ret, gfp, dma_coherent_ok);
    if (!page)
        return NULL;
    *dma_handle = phys_to_dma_direct(dev, page_to_phys(page));
    return ret;
}

static struct page *dma_direct_alloc_swiotlb(struct device *dev, size_t size)
{
    struct page *page = swiotlb_alloc(dev, size);

    if (page && !dma_coherent_ok(dev, page_to_phys(page), size)) {
        swiotlb_free(dev, page, size);
        return NULL;
    }

    return page;
}

static struct page *__dma_direct_alloc_pages(struct device *dev, size_t size,
        gfp_t gfp, bool allow_highmem)
{
    int node = dev_to_node(dev);
    struct page *page = NULL;
    u64 phys_limit;

    WARN_ON_ONCE(!PAGE_ALIGNED(size));

    if (is_swiotlb_for_alloc(dev))
        return dma_direct_alloc_swiotlb(dev, size);

    gfp |= dma_direct_optimal_gfp_mask(dev, &phys_limit);
    page = dma_alloc_contiguous(dev, size, gfp);
    if (page) {
        if (!dma_coherent_ok(dev, page_to_phys(page), size) ||
            (!allow_highmem && PageHighMem(page))) {
            dma_free_contiguous(dev, page, size);
            page = NULL;
        }
    }
again:
    if (!page)
        page = alloc_pages_node(node, gfp, get_order(size));
    if (page && !dma_coherent_ok(dev, page_to_phys(page), size)) {
        __free_pages(page, get_order(size));
        page = NULL;

        if (IS_ENABLED(CONFIG_ZONE_DMA32) &&
            phys_limit < DMA_BIT_MASK(64) &&
            !(gfp & (GFP_DMA32 | GFP_DMA))) {
            gfp |= GFP_DMA32;
            goto again;
        }

        if (IS_ENABLED(CONFIG_ZONE_DMA) && !(gfp & GFP_DMA)) {
            gfp = (gfp & ~GFP_DMA32) | GFP_DMA;
            goto again;
        }
    }

    return page;
}

void *dma_direct_alloc(struct device *dev, size_t size,
        dma_addr_t *dma_handle, gfp_t gfp, unsigned long attrs)
{
    bool remap = false, set_uncached = false;
    struct page *page;
    void *ret;
    size = PAGE_ALIGN(size);
    if (attrs & DMA_ATTR_NO_WARN)
        gfp |= __GFP_NOWARN;

    if ((attrs & DMA_ATTR_NO_KERNEL_MAPPING) &&
        !force_dma_unencrypted(dev) && !is_swiotlb_for_alloc(dev))
        return dma_direct_alloc_no_mapping(dev, size, dma_handle, gfp);

    if (!dev_is_dma_coherent(dev)) {
        if (IS_ENABLED(CONFIG_ARCH_HAS_DMA_ALLOC) &&
            !is_swiotlb_for_alloc(dev))
            return arch_dma_alloc(dev, size, dma_handle, gfp,
                          attrs);

        /*
         * If there is a global pool, always allocate from it for
         * non-coherent devices.
         */
        if (IS_ENABLED(CONFIG_DMA_GLOBAL_POOL))
            return dma_alloc_from_global_coherent(dev, size,
                    dma_handle);

        /*
         * Otherwise we require the architecture to either be able to
         * mark arbitrary parts of the kernel direct mapping uncached,
         * or remapped it uncached.
         */
        set_uncached = IS_ENABLED(CONFIG_ARCH_HAS_DMA_SET_UNCACHED);
        remap = IS_ENABLED(CONFIG_DMA_DIRECT_REMAP);
        if (!set_uncached && !remap) {
            pr_warn_once("coherent DMA allocations not supported on this platform.\n");
            return NULL;
        }
    }

    /*
     * Remapping or decrypting memory may block, allocate the memory from
     * the atomic pools instead if we aren't allowed block.
     */
    if ((remap || force_dma_unencrypted(dev)) &&
        dma_direct_use_pool(dev, gfp))
        return dma_direct_alloc_from_pool(dev, size, dma_handle, gfp);

    /* we always manually zero the memory once we are done */
    page = __dma_direct_alloc_pages(dev, size, gfp & ~__GFP_ZERO, true);
    if (!page)
        return NULL;

    /*
     * dma_alloc_contiguous can return highmem pages depending on a
     * combination the cma= arguments and per-arch setup.  These need to be
     * remapped to return a kernel virtual address.
     */
    if (PageHighMem(page)) {
        remap = true;
        set_uncached = false;
    }

    if (remap) {
#if 0
        pgprot_t prot = dma_pgprot(dev, PAGE_KERNEL, attrs);

        if (force_dma_unencrypted(dev))
            prot = pgprot_decrypted(prot);

        /* remove any dirty cache lines on the kernel alias */
        arch_dma_prep_coherent(page, size);

        /* create a coherent mapping */
        ret = dma_common_contiguous_remap(page, size, prot,
                __builtin_return_address(0));
        if (!ret)
            goto out_free_pages;
#endif
        PANIC("remap");
    } else {
        ret = page_address(page);
        if (dma_set_decrypted(dev, ret, size))
            goto out_leak_pages;
    }

    memset(ret, 0, size);

    if (set_uncached) {
        arch_dma_prep_coherent(page, size);
        ret = arch_dma_set_uncached(ret, size);
        if (IS_ERR(ret))
            goto out_encrypt_pages;
    }

    *dma_handle = phys_to_dma_direct(dev, page_to_phys(page));
    return ret;

out_encrypt_pages:
    if (dma_set_encrypted(dev, page_address(page), size))
        return NULL;
out_free_pages:
    __dma_direct_free_pages(dev, page, size);
    return NULL;
out_leak_pages:
    return NULL;
}

bool dma_coherent_ok(struct device *dev, phys_addr_t phys, size_t size)
{
    dma_addr_t dma_addr = phys_to_dma_direct(dev, phys);

    if (dma_addr == DMA_MAPPING_ERROR)
        return false;
    return dma_addr + size - 1 <=
        min_not_zero(dev->coherent_dma_mask, dev->bus_dma_limit);
}
