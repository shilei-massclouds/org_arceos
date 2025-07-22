#include <linux/dma-map-ops.h>

#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
bool dma_default_coherent = IS_ENABLED(CONFIG_ARCH_DMA_DEFAULT_COHERENT);
#endif

static int dma_supported(struct device *dev, u64 mask)
{
    pr_err("%s: No impl.", __func__);
    return 1;
}

static void dma_setup_need_sync(struct device *dev)
{
    pr_err("%s: No impl.", __func__);
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
