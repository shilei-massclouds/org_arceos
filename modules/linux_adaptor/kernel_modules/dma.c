#include <linux/device.h>

int dma_set_mask(struct device *dev, u64 mask)
{
    /*
     * Truncate the mask to the actually supported dma_addr_t width to
     * avoid generating unsupportable addresses.
     */
    mask = (dma_addr_t)mask;
    *dev->dma_mask = mask;
    return 0;
}

int dma_set_coherent_mask(struct device *dev, u64 mask)
{
    /*
     * Truncate the mask to the actually supported dma_addr_t width to
     * avoid generating unsupportable addresses.
     */
    mask = (dma_addr_t)mask;
    dev->coherent_dma_mask = mask;
    return 0;
}

