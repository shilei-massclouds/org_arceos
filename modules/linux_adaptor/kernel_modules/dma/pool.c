#include <linux/cma.h>
#include <linux/debugfs.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-direct.h>
#include <linux/init.h>
#include <linux/genalloc.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "../adaptor.h"

static struct gen_pool *atomic_pool_dma __ro_after_init;
static unsigned long pool_size_dma;
static struct gen_pool *atomic_pool_dma32 __ro_after_init;
static unsigned long pool_size_dma32;
static struct gen_pool *atomic_pool_kernel __ro_after_init;
static unsigned long pool_size_kernel;

/* Size can be defined by the coherent_pool command line */
static size_t atomic_pool_size;

/* Dynamic background expansion when the atomic pool is near capacity */
static struct work_struct atomic_pool_work;

struct page *dma_alloc_from_pool(struct device *dev, size_t size,
        void **cpu_addr, gfp_t gfp,
        bool (*phys_addr_ok)(struct device *, phys_addr_t, size_t))
{
    struct gen_pool *pool = NULL;
    struct page *page;

#if 0
    while ((pool = dma_guess_pool(pool, gfp))) {
        page = __dma_alloc_from_pool(dev, size, pool, cpu_addr,
                         phys_addr_ok);
        if (page)
            return page;
    }

    WARN(1, "Failed to get suitable pool for %s\n", dev_name(dev));
#endif
    PANIC("");
    return NULL;
}
