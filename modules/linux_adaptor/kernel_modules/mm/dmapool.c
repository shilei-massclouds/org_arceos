#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/poison.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "../adaptor.h"

#ifdef CONFIG_SLUB_DEBUG_ON
#define DMAPOOL_DEBUG 1
#endif

struct dma_block {
    struct dma_block *next_block;
    dma_addr_t dma;
};

struct dma_pool {       /* the pool */
    struct list_head page_list;
    spinlock_t lock;
    struct dma_block *next_block;
    size_t nr_blocks;
    size_t nr_active;
    size_t nr_pages;
    struct device *dev;
    unsigned int size;
    unsigned int allocation;
    unsigned int boundary;
    char name[32];
    struct list_head pools;
};

struct dma_page {       /* cacheable header for 'allocation' bytes */
    struct list_head page_list;
    void *vaddr;
    dma_addr_t dma;
};

static DEFINE_MUTEX(pools_lock);
static DEFINE_MUTEX(pools_reg_lock);

static ssize_t pools_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct dma_pool *pool;
    unsigned size;

    size = sysfs_emit(buf, "poolinfo - 0.1\n");

    mutex_lock(&pools_lock);
    list_for_each_entry(pool, &dev->dma_pools, pools) {
        /* per-pool info, no real statistics yet */
        size += sysfs_emit_at(buf, size, "%-16s %4zu %4zu %4u %2zu\n",
                      pool->name, pool->nr_active,
                      pool->nr_blocks, pool->size,
                      pool->nr_pages);
    }
    mutex_unlock(&pools_lock);

    return size;
}

static DEVICE_ATTR_RO(pools);

/**
 * dma_pool_create - Creates a pool of consistent memory blocks, for dma.
 * @name: name of pool, for diagnostics
 * @dev: device that will be doing the DMA
 * @size: size of the blocks in this pool.
 * @align: alignment requirement for blocks; must be a power of two
 * @boundary: returned blocks won't cross this power of two boundary
 * Context: not in_interrupt()
 *
 * Given one of these pools, dma_pool_alloc()
 * may be used to allocate memory.  Such memory will all have "consistent"
 * DMA mappings, accessible by the device and its driver without using
 * cache flushing primitives.  The actual size of blocks allocated may be
 * larger than requested because of alignment.
 *
 * If @boundary is nonzero, objects returned from dma_pool_alloc() won't
 * cross that size boundary.  This is useful for devices which have
 * addressing restrictions on individual DMA transfers, such as not crossing
 * boundaries of 4KBytes.
 *
 * Return: a dma allocation pool with the requested characteristics, or
 * %NULL if one can't be created.
 */
struct dma_pool *dma_pool_create(const char *name, struct device *dev,
                 size_t size, size_t align, size_t boundary)
{
    struct dma_pool *retval;
    size_t allocation;
    bool empty;

    if (!dev)
        return NULL;

    if (align == 0)
        align = 1;
    else if (align & (align - 1))
        return NULL;

    if (size == 0 || size > INT_MAX)
        return NULL;
    if (size < sizeof(struct dma_block))
        size = sizeof(struct dma_block);

    size = ALIGN(size, align);
    allocation = max_t(size_t, size, PAGE_SIZE);

    if (!boundary)
        boundary = allocation;
    else if ((boundary < size) || (boundary & (boundary - 1)))
        return NULL;

    boundary = min(boundary, allocation);

    retval = kzalloc(sizeof(*retval), GFP_KERNEL);
    if (!retval)
        return retval;

    strscpy(retval->name, name, sizeof(retval->name));

    retval->dev = dev;

    INIT_LIST_HEAD(&retval->page_list);
    spin_lock_init(&retval->lock);
    retval->size = size;
    retval->boundary = boundary;
    retval->allocation = allocation;
    INIT_LIST_HEAD(&retval->pools);

    /*
     * pools_lock ensures that the ->dma_pools list does not get corrupted.
     * pools_reg_lock ensures that there is not a race between
     * dma_pool_create() and dma_pool_destroy() or within dma_pool_create()
     * when the first invocation of dma_pool_create() failed on
     * device_create_file() and the second assumes that it has been done (I
     * know it is a short window).
     */
    mutex_lock(&pools_reg_lock);
    mutex_lock(&pools_lock);
    empty = list_empty(&dev->dma_pools);
    list_add(&retval->pools, &dev->dma_pools);
    mutex_unlock(&pools_lock);
    if (empty) {
        int err;

        err = device_create_file(dev, &dev_attr_pools);
        if (err) {
            mutex_lock(&pools_lock);
            list_del(&retval->pools);
            mutex_unlock(&pools_lock);
            mutex_unlock(&pools_reg_lock);
            kfree(retval);
            return NULL;
        }
    }
    mutex_unlock(&pools_reg_lock);
    return retval;
}
