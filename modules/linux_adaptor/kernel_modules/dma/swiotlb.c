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
