#include <linux/io.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#include "../adaptor.h"

static inline struct dma_coherent_mem *dev_get_coherent_memory(struct device *dev)
{
    if (dev && dev->dma_mem)
        return dev->dma_mem;
    return NULL;
}

static void *__dma_alloc_from_coherent(struct device *dev,
                       struct dma_coherent_mem *mem,
                       ssize_t size, dma_addr_t *dma_handle)
{
    int order = get_order(size);
    unsigned long flags;
    int pageno;
    void *ret;

#if 0
    spin_lock_irqsave(&mem->spinlock, flags);

    if (unlikely(size > ((dma_addr_t)mem->size << PAGE_SHIFT)))
        goto err;

    pageno = bitmap_find_free_region(mem->bitmap, mem->size, order);
    if (unlikely(pageno < 0))
        goto err;

    /*
     * Memory was found in the coherent area.
     */
    *dma_handle = dma_get_device_base(dev, mem) +
            ((dma_addr_t)pageno << PAGE_SHIFT);
    ret = mem->virt_base + ((dma_addr_t)pageno << PAGE_SHIFT);
    spin_unlock_irqrestore(&mem->spinlock, flags);
    memset(ret, 0, size);
    return ret;
err:
    spin_unlock_irqrestore(&mem->spinlock, flags);
    return NULL;
#endif
    PANIC("");
}

/**
 * dma_alloc_from_dev_coherent() - allocate memory from device coherent pool
 * @dev:    device from which we allocate memory
 * @size:   size of requested memory area
 * @dma_handle: This will be filled with the correct dma handle
 * @ret:    This pointer will be filled with the virtual address
 *      to allocated area.
 *
 * This function should be only called from per-arch dma_alloc_coherent()
 * to support allocation from per-device coherent memory pools.
 *
 * Returns 0 if dma_alloc_coherent should continue with allocating from
 * generic memory areas, or !0 if dma_alloc_coherent should return @ret.
 */
int dma_alloc_from_dev_coherent(struct device *dev, ssize_t size,
        dma_addr_t *dma_handle, void **ret)
{
    struct dma_coherent_mem *mem = dev_get_coherent_memory(dev);

    if (!mem)
        return 0;

    *ret = __dma_alloc_from_coherent(dev, mem, size, dma_handle);
    return 1;
}
