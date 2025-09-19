#include <linux/swiotlb.h>

static struct io_tlb_mem io_tlb_default_mem;

/**
 * swiotlb_dev_init() - initialize swiotlb fields in &struct device
 * @dev:    Device to be initialized.
 */
void swiotlb_dev_init(struct device *dev)
{
    dev->dma_io_tlb_mem = &io_tlb_default_mem;
#ifdef CONFIG_SWIOTLB_DYNAMIC
    INIT_LIST_HEAD(&dev->dma_io_tlb_pools);
    spin_lock_init(&dev->dma_io_tlb_lock);
    dev->dma_uses_io_tlb = false;
#endif
}

bool is_swiotlb_active(struct device *dev)
{
    struct io_tlb_mem *mem = dev->dma_io_tlb_mem;

    return mem && mem->nslabs;
}

static inline unsigned int dma_get_min_align_mask(struct device *dev)
{
    if (dev->dma_parms)
        return dev->dma_parms->min_align_mask;
    return 0;
}

size_t swiotlb_max_mapping_size(struct device *dev)
{
    int min_align_mask = dma_get_min_align_mask(dev);
    int min_align = 0;

    /*
     * swiotlb_find_slots() skips slots according to
     * min align mask. This affects max mapping size.
     * Take it into acount here.
     */
    if (min_align_mask)
        min_align = roundup(min_align_mask, IO_TLB_SIZE);

    return ((size_t)IO_TLB_SIZE) * IO_TLB_SEGSIZE - min_align;
}
