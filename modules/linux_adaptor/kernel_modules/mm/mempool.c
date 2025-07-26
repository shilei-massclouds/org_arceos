#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/kasan.h>
#include <linux/kmemleak.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/writeback.h>
#include "slab.h"

#include "../adaptor.h"

static inline void check_element(mempool_t *pool, void *element)
{
}
static inline void poison_element(mempool_t *pool, void *element)
{
}

static __always_inline bool kasan_poison_element(mempool_t *pool, void *element)
{
    if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
        return kasan_mempool_poison_object(element);
    else if (pool->alloc == mempool_alloc_pages)
        return kasan_mempool_poison_pages(element,
                        (unsigned long)pool->pool_data);
    return true;
}

static void kasan_unpoison_element(mempool_t *pool, void *element)
{
    if (pool->alloc == mempool_kmalloc)
        kasan_mempool_unpoison_object(element, (size_t)pool->pool_data);
    else if (pool->alloc == mempool_alloc_slab)
        kasan_mempool_unpoison_object(element,
                          kmem_cache_size(pool->pool_data));
    else if (pool->alloc == mempool_alloc_pages)
        kasan_mempool_unpoison_pages(element,
                         (unsigned long)pool->pool_data);
}

static __always_inline void add_element(mempool_t *pool, void *element)
{
    BUG_ON(pool->curr_nr >= pool->min_nr);
    poison_element(pool, element);
    if (kasan_poison_element(pool, element))
        pool->elements[pool->curr_nr++] = element;
}

static void *remove_element(mempool_t *pool)
{
    void *element = pool->elements[--pool->curr_nr];

    BUG_ON(pool->curr_nr < 0);
    kasan_unpoison_element(pool, element);
    check_element(pool, element);
    return element;
}

/**
 * mempool_init - initialize a memory pool
 * @pool:      pointer to the memory pool that should be initialized
 * @min_nr:    the minimum number of elements guaranteed to be
 *             allocated for this pool.
 * @alloc_fn:  user-defined element-allocation function.
 * @free_fn:   user-defined element-freeing function.
 * @pool_data: optional private data available to the user-defined functions.
 *
 * Like mempool_create(), but initializes the pool in (i.e. embedded in another
 * structure).
 *
 * Return: %0 on success, negative error code otherwise.
 */
int mempool_init_noprof(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
            mempool_free_t *free_fn, void *pool_data)
{
    return mempool_init_node(pool, min_nr, alloc_fn, free_fn,
                 pool_data, GFP_KERNEL, NUMA_NO_NODE);

}

int mempool_init_node(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
              mempool_free_t *free_fn, void *pool_data,
              gfp_t gfp_mask, int node_id)
{
    printk("%s: pool(%lx) alloc_fn(%lx)\n", __func__, pool, alloc_fn);
    spin_lock_init(&pool->lock);
    pool->min_nr    = min_nr;
    pool->pool_data = pool_data;
    pool->alloc = alloc_fn;
    pool->free  = free_fn;
    init_waitqueue_head(&pool->wait);

    pool->elements = kmalloc_array_node(min_nr, sizeof(void *),
                        gfp_mask, node_id);
    if (!pool->elements)
        return -ENOMEM;

    /*
     * First pre-allocate the guaranteed number of buffers.
     */
    while (pool->curr_nr < pool->min_nr) {
        void *element;

        element = pool->alloc(gfp_mask, pool->pool_data);
        if (unlikely(!element)) {
            mempool_exit(pool);
            return -ENOMEM;
        }
        add_element(pool, element);
    }

    return 0;
}

/**
 * mempool_exit - exit a mempool initialized with mempool_init()
 * @pool:      pointer to the memory pool which was initialized with
 *             mempool_init().
 *
 * Free all reserved elements in @pool and @pool itself.  This function
 * only sleeps if the free_fn() function sleeps.
 *
 * May be called on a zeroed but uninitialized mempool (i.e. allocated with
 * kzalloc()).
 */
void mempool_exit(mempool_t *pool)
{
    while (pool->curr_nr) {
        void *element = remove_element(pool);
        pool->free(element, pool->pool_data);
    }
    kfree(pool->elements);
    pool->elements = NULL;
}

/*
 * A commonly used alloc and free fn that kmalloc/kfrees the amount of memory
 * specified by pool_data
 */
void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data)
{
    size_t size = (size_t)pool_data;
    return kmalloc_noprof(size, gfp_mask);
}

void mempool_kfree(void *element, void *pool_data)
{
    kfree(element);
}

/*
 * A commonly used alloc and free fn.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
{
    struct kmem_cache *mem = pool_data;
    VM_BUG_ON(mem->ctor);
    return kmem_cache_alloc_noprof(mem, gfp_mask);
}

void mempool_free_slab(void *element, void *pool_data)
{
    struct kmem_cache *mem = pool_data;
    kmem_cache_free(mem, element);
}

/**
 * mempool_alloc - allocate an element from a specific memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 * @gfp_mask:  the usual allocation bitmask.
 *
 * this function only sleeps if the alloc_fn() function sleeps or
 * returns NULL. Note that due to preallocation, this function
 * *never* fails when called from process contexts. (it might
 * fail if called from an IRQ context.)
 * Note: using __GFP_ZERO is not supported.
 *
 * Return: pointer to the allocated element or %NULL on error.
 */
void *mempool_alloc_noprof(mempool_t *pool, gfp_t gfp_mask)
{
    void *element;
    unsigned long flags;
    wait_queue_entry_t wait;
    gfp_t gfp_temp;

    VM_WARN_ON_ONCE(gfp_mask & __GFP_ZERO);
    might_alloc(gfp_mask);

    gfp_mask |= __GFP_NOMEMALLOC;   /* don't allocate emergency reserves */
    gfp_mask |= __GFP_NORETRY;  /* don't loop in __alloc_pages */
    gfp_mask |= __GFP_NOWARN;   /* failures are OK */

    gfp_temp = gfp_mask & ~(__GFP_DIRECT_RECLAIM|__GFP_IO);

repeat_alloc:

    printk("%s: step1 pool(%lx) alloc(%lx)\n", __func__, pool, pool->alloc);
    element = pool->alloc(gfp_temp, pool->pool_data);
    printk("%s: step2\n", __func__);
    if (likely(element != NULL))
        return element;

#if 0
    spin_lock_irqsave(&pool->lock, flags);
    if (likely(pool->curr_nr)) {
        element = remove_element(pool);
        spin_unlock_irqrestore(&pool->lock, flags);
        /* paired with rmb in mempool_free(), read comment there */
        smp_wmb();
        /*
         * Update the allocation stack trace as this is more useful
         * for debugging.
         */
        kmemleak_update_trace(element);
        return element;
    }

    /*
     * We use gfp mask w/o direct reclaim or IO for the first round.  If
     * alloc failed with that and @pool was empty, retry immediately.
     */
    if (gfp_temp != gfp_mask) {
        spin_unlock_irqrestore(&pool->lock, flags);
        gfp_temp = gfp_mask;
        goto repeat_alloc;
    }

    /* We must not sleep if !__GFP_DIRECT_RECLAIM */
    if (!(gfp_mask & __GFP_DIRECT_RECLAIM)) {
        spin_unlock_irqrestore(&pool->lock, flags);
        return NULL;
    }

    /* Let's wait for someone else to return an element to @pool */
    init_wait(&wait);
    prepare_to_wait(&pool->wait, &wait, TASK_UNINTERRUPTIBLE);

    spin_unlock_irqrestore(&pool->lock, flags);

    /*
     * FIXME: this should be io_schedule().  The timeout is there as a
     * workaround for some DM problems in 2.6.18.
     */
    io_schedule_timeout(5*HZ);

    finish_wait(&pool->wait, &wait);
    goto repeat_alloc;
#endif

    PANIC("");
}

/**
 * mempool_free - return an element to the pool.
 * @element:   pool element pointer.
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 *
 * this function only sleeps if the free_fn() function sleeps.
 */
void mempool_free(void *element, mempool_t *pool)
{
    unsigned long flags;

    if (unlikely(element == NULL))
        return;

    /*
     * Paired with the wmb in mempool_alloc().  The preceding read is
     * for @element and the following @pool->curr_nr.  This ensures
     * that the visible value of @pool->curr_nr is from after the
     * allocation of @element.  This is necessary for fringe cases
     * where @element was passed to this task without going through
     * barriers.
     *
     * For example, assume @p is %NULL at the beginning and one task
     * performs "p = mempool_alloc(...);" while another task is doing
     * "while (!p) cpu_relax(); mempool_free(p, ...);".  This function
     * may end up using curr_nr value which is from before allocation
     * of @p without the following rmb.
     */
    smp_rmb();

    /*
     * For correctness, we need a test which is guaranteed to trigger
     * if curr_nr + #allocated == min_nr.  Testing curr_nr < min_nr
     * without locking achieves that and refilling as soon as possible
     * is desirable.
     *
     * Because curr_nr visible here is always a value after the
     * allocation of @element, any task which decremented curr_nr below
     * min_nr is guaranteed to see curr_nr < min_nr unless curr_nr gets
     * incremented to min_nr afterwards.  If curr_nr gets incremented
     * to min_nr after the allocation of @element, the elements
     * allocated after that are subject to the same guarantee.
     *
     * Waiters happen iff curr_nr is 0 and the above guarantee also
     * ensures that there will be frees which return elements to the
     * pool waking up the waiters.
     */
    if (unlikely(READ_ONCE(pool->curr_nr) < pool->min_nr)) {
        spin_lock_irqsave(&pool->lock, flags);
        if (likely(pool->curr_nr < pool->min_nr)) {
            add_element(pool, element);
            spin_unlock_irqrestore(&pool->lock, flags);
            wake_up(&pool->wait);
            return;
        }
        spin_unlock_irqrestore(&pool->lock, flags);
    }
    pool->free(element, pool->pool_data);
}

/**
 * mempool_create_node - create a memory pool
 * @min_nr:    the minimum number of elements guaranteed to be
 *             allocated for this pool.
 * @alloc_fn:  user-defined element-allocation function.
 * @free_fn:   user-defined element-freeing function.
 * @pool_data: optional private data available to the user-defined functions.
 * @gfp_mask:  memory allocation flags
 * @node_id:   numa node to allocate on
 *
 * this function creates and allocates a guaranteed size, preallocated
 * memory pool. The pool can be used from the mempool_alloc() and mempool_free()
 * functions. This function might sleep. Both the alloc_fn() and the free_fn()
 * functions might sleep - as long as the mempool_alloc() function is not called
 * from IRQ contexts.
 *
 * Return: pointer to the created memory pool object or %NULL on error.
 */
mempool_t *mempool_create_node_noprof(int min_nr, mempool_alloc_t *alloc_fn,
                      mempool_free_t *free_fn, void *pool_data,
                      gfp_t gfp_mask, int node_id)
{
    mempool_t *pool;

    pool = kmalloc_node_noprof(sizeof(*pool), gfp_mask | __GFP_ZERO, node_id);
    if (!pool)
        return NULL;

    if (mempool_init_node(pool, min_nr, alloc_fn, free_fn, pool_data,
                  gfp_mask, node_id)) {
        kfree(pool);
        return NULL;
    }

    return pool;
}
