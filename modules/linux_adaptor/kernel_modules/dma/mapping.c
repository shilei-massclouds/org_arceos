#include <linux/memblock.h> /* for max_pfn */
#include <linux/acpi.h>
#include <linux/dma-map-ops.h>
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/iommu-dma.h>
#include <linux/kmsan.h>
#include <linux/of_device.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "debug.h"
#include "direct.h"
#include "../adaptor.h"

#define CREATE_TRACE_POINTS
#include <trace/events/dma.h>

#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
bool dma_default_coherent = IS_ENABLED(CONFIG_ARCH_DMA_DEFAULT_COHERENT);
#endif

static int dma_supported(struct device *dev, u64 mask)
{
    pr_notice("%s: No impl.", __func__);
    return 1;
}

static void dma_setup_need_sync(struct device *dev)
{
    pr_notice("%s: No impl.", __func__);
}

int dma_set_mask(struct device *dev, u64 mask)
{
    /*
     * Truncate the mask to the actually supported dma_addr_t width to
     * avoid generating unsupportable addresses.
     */
    mask = (dma_addr_t)mask;

    if (!dev->dma_mask || !dma_supported(dev, mask))
        return -EIO;

    arch_dma_set_mask(dev, mask);
    *dev->dma_mask = mask;
    dma_setup_need_sync(dev);

    return 0;
}

int dma_set_coherent_mask(struct device *dev, u64 mask)
{
    /*
     * Truncate the mask to the actually supported dma_addr_t width to
     * avoid generating unsupportable addresses.
     */
    mask = (dma_addr_t)mask;

    if (!dma_supported(dev, mask))
        return -EIO;

    dev->coherent_dma_mask = mask;
    return 0;
}

size_t dma_opt_mapping_size(struct device *dev)
{
    const struct dma_map_ops *ops = get_dma_ops(dev);
    size_t size = SIZE_MAX;

    if (use_dma_iommu(dev))
        size = iommu_dma_opt_mapping_size();
    else if (ops && ops->opt_mapping_size)
        size = ops->opt_mapping_size();

    return min(dma_max_mapping_size(dev), size);
}

static bool dma_go_direct(struct device *dev, dma_addr_t mask,
        const struct dma_map_ops *ops)
{
    if (use_dma_iommu(dev))
        return false;

    if (likely(!ops))
        return true;

#ifdef CONFIG_DMA_OPS_BYPASS
    if (dev->dma_ops_bypass)
        return min_not_zero(mask, dev->bus_dma_limit) >=
                dma_direct_get_required_mask(dev);
#endif
    return false;
}

static inline bool dma_map_direct(struct device *dev,
        const struct dma_map_ops *ops)
{
    return dma_go_direct(dev, *dev->dma_mask, ops);
}

/*
 * Check if the devices uses a direct mapping for streaming DMA operations.
 * This allows IOMMU drivers to set a bypass mode if the DMA mask is large
 * enough.
 */
static inline bool dma_alloc_direct(struct device *dev,
        const struct dma_map_ops *ops)
{
    return dma_go_direct(dev, dev->coherent_dma_mask, ops);
}

size_t dma_max_mapping_size(struct device *dev)
{
    const struct dma_map_ops *ops = get_dma_ops(dev);
    size_t size = SIZE_MAX;

    if (dma_map_direct(dev, ops))
        size = dma_direct_max_mapping_size(dev);
    else if (use_dma_iommu(dev))
        size = iommu_dma_max_mapping_size(dev);
    else if (ops && ops->max_mapping_size)
        size = ops->max_mapping_size(dev);

    return size;
}

void *dma_alloc_attrs(struct device *dev, size_t size, dma_addr_t *dma_handle,
        gfp_t flag, unsigned long attrs)
{
    const struct dma_map_ops *ops = get_dma_ops(dev);
    void *cpu_addr;

    WARN_ON_ONCE(!dev->coherent_dma_mask);

    /*
     * DMA allocations can never be turned back into a page pointer, so
     * requesting compound pages doesn't make sense (and can't even be
     * supported at all by various backends).
     */
    if (WARN_ON_ONCE(flag & __GFP_COMP))
        return NULL;

    if (dma_alloc_from_dev_coherent(dev, size, dma_handle, &cpu_addr))
        return cpu_addr;

    /* let the implementation decide on the zone to allocate from: */
    flag &= ~(__GFP_DMA | __GFP_DMA32 | __GFP_HIGHMEM);

    if (dma_alloc_direct(dev, ops))
        cpu_addr = dma_direct_alloc(dev, size, dma_handle, flag, attrs);
    else if (use_dma_iommu(dev))
        cpu_addr = iommu_dma_alloc(dev, size, dma_handle, flag, attrs);
    else if (ops->alloc)
        cpu_addr = ops->alloc(dev, size, dma_handle, flag, attrs);
    else
        return NULL;

    trace_dma_alloc(dev, cpu_addr, *dma_handle, size, flag, attrs);
    debug_dma_alloc_coherent(dev, size, *dma_handle, cpu_addr, attrs);
    return cpu_addr;
}

static bool __dma_addressing_limited(struct device *dev)
{
    const struct dma_map_ops *ops = get_dma_ops(dev);

#if 0
    if (min_not_zero(dma_get_mask(dev), dev->bus_dma_limit) <
             dma_get_required_mask(dev))
        return true;

    if (unlikely(ops) || use_dma_iommu(dev))
        return false;
    return !dma_direct_all_ram_mapped(dev);
#endif
    PANIC("");
}

/**
 * dma_addressing_limited - return if the device is addressing limited
 * @dev:    device to check
 *
 * Return %true if the devices DMA mask is too small to address all memory in
 * the system, else %false.  Lack of addressing bits is the prime reason for
 * bounce buffering, but might not be the only one.
 */
bool dma_addressing_limited(struct device *dev)
{
    if (!__dma_addressing_limited(dev))
        return false;

    dev_dbg(dev, "device is DMA addressing limited\n");
    return true;
}

dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
        size_t offset, size_t size, enum dma_data_direction dir,
        unsigned long attrs)
{
    const struct dma_map_ops *ops = get_dma_ops(dev);
    dma_addr_t addr;

    BUG_ON(!valid_dma_direction(dir));

    if (WARN_ON_ONCE(!dev->dma_mask))
        return DMA_MAPPING_ERROR;

    if (dma_map_direct(dev, ops) ||
        arch_dma_map_page_direct(dev, page_to_phys(page) + offset + size))
        addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
    else if (use_dma_iommu(dev))
        addr = iommu_dma_map_page(dev, page, offset, size, dir, attrs);
    else
        addr = ops->map_page(dev, page, offset, size, dir, attrs);
    kmsan_handle_dma(page, offset, size, dir);
    trace_dma_map_page(dev, page_to_phys(page) + offset, addr, size, dir,
               attrs);
    debug_dma_map_page(dev, page, offset, size, dir, addr, attrs);

    return addr;
}

void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
        enum dma_data_direction dir, unsigned long attrs)
{
    const struct dma_map_ops *ops = get_dma_ops(dev);

    BUG_ON(!valid_dma_direction(dir));
    if (dma_map_direct(dev, ops) ||
        arch_dma_unmap_page_direct(dev, addr + size))
        dma_direct_unmap_page(dev, addr, size, dir, attrs);
    else if (use_dma_iommu(dev))
        iommu_dma_unmap_page(dev, addr, size, dir, attrs);
    else
        ops->unmap_page(dev, addr, size, dir, attrs);
    trace_dma_unmap_page(dev, addr, size, dir, attrs);
    debug_dma_unmap_page(dev, addr, size, dir);
}

bool dma_pci_p2pdma_supported(struct device *dev)
{
    const struct dma_map_ops *ops = get_dma_ops(dev);

    /*
     * Note: dma_ops_bypass is not checked here because P2PDMA should
     * not be used with dma mapping ops that do not have support even
     * if the specific device is bypassing them.
     */

    /* if ops is not set, dma direct and default IOMMU support P2PDMA */
    return !ops;
}

static int __dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
     int nents, enum dma_data_direction dir, unsigned long attrs)
{
    const struct dma_map_ops *ops = get_dma_ops(dev);
    int ents;

    BUG_ON(!valid_dma_direction(dir));

    if (WARN_ON_ONCE(!dev->dma_mask))
        return 0;

    if (dma_map_direct(dev, ops) ||
        arch_dma_map_sg_direct(dev, sg, nents))
        ents = dma_direct_map_sg(dev, sg, nents, dir, attrs);
    else if (use_dma_iommu(dev))
        ents = iommu_dma_map_sg(dev, sg, nents, dir, attrs);
    else
        ents = ops->map_sg(dev, sg, nents, dir, attrs);

    if (ents > 0) {
        kmsan_handle_dma_sg(sg, nents, dir);
        trace_dma_map_sg(dev, sg, nents, ents, dir, attrs);
        debug_dma_map_sg(dev, sg, nents, ents, dir, attrs);
    } else if (WARN_ON_ONCE(ents != -EINVAL && ents != -ENOMEM &&
                ents != -EIO && ents != -EREMOTEIO)) {
        return -EIO;
    }

    return ents;
}

/**
 * dma_map_sgtable - Map the given buffer for DMA
 * @dev:    The device for which to perform the DMA operation
 * @sgt:    The sg_table object describing the buffer
 * @dir:    DMA direction
 * @attrs:  Optional DMA attributes for the map operation
 *
 * Maps a buffer described by a scatterlist stored in the given sg_table
 * object for the @dir DMA operation by the @dev device. After success, the
 * ownership for the buffer is transferred to the DMA domain.  One has to
 * call dma_sync_sgtable_for_cpu() or dma_unmap_sgtable() to move the
 * ownership of the buffer back to the CPU domain before touching the
 * buffer by the CPU.
 *
 * Returns 0 on success or a negative error code on error. The following
 * error codes are supported with the given meaning:
 *
 *   -EINVAL        An invalid argument, unaligned access or other error
 *          in usage. Will not succeed if retried.
 *   -ENOMEM        Insufficient resources (like memory or IOVA space) to
 *          complete the mapping. Should succeed if retried later.
 *   -EIO       Legacy error code with an unknown meaning. eg. this is
 *          returned if a lower level call returned
 *          DMA_MAPPING_ERROR.
 *   -EREMOTEIO     The DMA device cannot access P2PDMA memory specified
 *          in the sg_table. This will not succeed if retried.
 */
int dma_map_sgtable(struct device *dev, struct sg_table *sgt,
            enum dma_data_direction dir, unsigned long attrs)
{
    int nents;

    nents = __dma_map_sg_attrs(dev, sgt->sgl, sgt->orig_nents, dir, attrs);
    if (nents < 0)
        return nents;
    sgt->nents = nents;
    return 0;
}

void dma_unmap_sg_attrs(struct device *dev, struct scatterlist *sg,
                      int nents, enum dma_data_direction dir,
                      unsigned long attrs)
{
    const struct dma_map_ops *ops = get_dma_ops(dev);

    BUG_ON(!valid_dma_direction(dir));
    trace_dma_unmap_sg(dev, sg, nents, dir, attrs);
    debug_dma_unmap_sg(dev, sg, nents, dir);
    if (dma_map_direct(dev, ops) ||
        arch_dma_unmap_sg_direct(dev, sg, nents))
        dma_direct_unmap_sg(dev, sg, nents, dir, attrs);
    else if (use_dma_iommu(dev))
        iommu_dma_unmap_sg(dev, sg, nents, dir, attrs);
    else if (ops->unmap_sg)
        ops->unmap_sg(dev, sg, nents, dir, attrs);
}
