#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/percpu.h>

#include <asm/sections.h>

#include "base.h"
#include "trace.h"
#include "../adaptor.h"

struct devres_node {
    struct list_head        entry;
    dr_release_t            release;
    const char          *name;
    size_t              size;
};

struct devres {
    struct devres_node      node;
    /*
     * Some archs want to perform DMA into kmalloc caches
     * and need a guaranteed alignment larger than
     * the alignment of a 64-bit integer.
     * Thus we use ARCH_DMA_MINALIGN for data[] which will force the same
     * alignment for struct devres when allocated by kmalloc().
     */
    u8 __aligned(ARCH_DMA_MINALIGN) data[];
};

static void set_node_dbginfo(struct devres_node *node, const char *name,
                 size_t size)
{
    node->name = name;
    node->size = size;
}

/*
 * Managed kmalloc/kfree
 */
static void devm_kmalloc_release(struct device *dev, void *res)
{
    /* noop */
}

static bool check_dr_size(size_t size, size_t *tot_size)
{
    /* We must catch any near-SIZE_MAX cases that could overflow. */
    if (unlikely(check_add_overflow(sizeof(struct devres),
                    size, tot_size)))
        return false;

    /* Actually allocate the full kmalloc bucket size. */
    *tot_size = kmalloc_size_roundup(*tot_size);

    return true;
}

/**
 * devm_kasprintf - Allocate resource managed space and format a string
 *          into that.
 * @dev: Device to allocate memory for
 * @gfp: the GFP mask used in the devm_kmalloc() call when
 *       allocating memory
 * @fmt: The printf()-style format string
 * @...: Arguments for the format string
 * RETURNS:
 * Pointer to allocated string on success, NULL on failure.
 */
char *devm_kasprintf(struct device *dev, gfp_t gfp, const char *fmt, ...)
{
    va_list ap;
    char *p;

    va_start(ap, fmt);
    p = devm_kvasprintf(dev, gfp, fmt, ap);
    va_end(ap);

    return p;
}

/**
 * devm_kvasprintf - Allocate resource managed space and format a string
 *           into that.
 * @dev: Device to allocate memory for
 * @gfp: the GFP mask used in the devm_kmalloc() call when
 *       allocating memory
 * @fmt: The printf()-style format string
 * @ap: Arguments for the format string
 * RETURNS:
 * Pointer to allocated string on success, NULL on failure.
 */
char *devm_kvasprintf(struct device *dev, gfp_t gfp, const char *fmt,
              va_list ap)
{
    unsigned int len;
    char *p;
    va_list aq;

    va_copy(aq, ap);
    len = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);

    p = devm_kmalloc(dev, len+1, gfp);
    if (!p)
        return NULL;

    vsnprintf(p, len+1, fmt, ap);

    return p;
}

static __always_inline struct devres *alloc_dr(dr_release_t release,
                           size_t size, gfp_t gfp, int nid)
{
    size_t tot_size;
    struct devres *dr;

    if (!check_dr_size(size, &tot_size))
        return NULL;

    dr = kmalloc_node_track_caller(tot_size, gfp, nid);
    if (unlikely(!dr))
        return NULL;

    /* No need to clear memory twice */
    if (!(gfp & __GFP_ZERO))
        memset(dr, 0, offsetof(struct devres, data));

    INIT_LIST_HEAD(&dr->node.entry);
    dr->node.release = release;
    return dr;
}

/**
 * devm_kmalloc - Resource-managed kmalloc
 * @dev: Device to allocate memory for
 * @size: Allocation size
 * @gfp: Allocation gfp flags
 *
 * Managed kmalloc.  Memory allocated with this function is
 * automatically freed on driver detach.  Like all other devres
 * resources, guaranteed alignment is unsigned long long.
 *
 * RETURNS:
 * Pointer to allocated memory on success, NULL on failure.
 */
void *devm_kmalloc(struct device *dev, size_t size, gfp_t gfp)
{
    struct devres *dr;

    if (unlikely(!size))
        return ZERO_SIZE_PTR;

    /* use raw alloc_dr for kmalloc caller tracing */
    dr = alloc_dr(devm_kmalloc_release, size, gfp, dev_to_node(dev));
    if (unlikely(!dr))
        return NULL;

    /*
     * This is named devm_kzalloc_release for historical reasons
     * The initial implementation did not support kmalloc, only kzalloc
     */
    set_node_dbginfo(&dr->node, "devm_kzalloc_release", size);
    devres_add(dev, dr->data);
    return dr->data;
}

static void devres_log(struct device *dev, struct devres_node *node,
               const char *op)
{
    trace_devres_log(dev, op, node, node->name, node->size);
    //devres_dbg(dev, node, op);
    pr_notice("DEVRES %3s %p %s (%zu bytes)\n", op, node, node->name, node->size);
}

static void add_dr(struct device *dev, struct devres_node *node)
{
    devres_log(dev, node, "ADD");
    BUG_ON(!list_empty(&node->entry));
    list_add_tail(&node->entry, &dev->devres_head);
}

/**
 * devres_add - Register device resource
 * @dev: Device to add resource to
 * @res: Resource to register
 *
 * Register devres @res to @dev.  @res should have been allocated
 * using devres_alloc().  On driver detach, the associated release
 * function will be invoked and devres will be freed automatically.
 */
void devres_add(struct device *dev, void *res)
{
    struct devres *dr = container_of(res, struct devres, data);
    unsigned long flags;

    spin_lock_irqsave(&dev->devres_lock, flags);
    add_dr(dev, &dr->node);
    spin_unlock_irqrestore(&dev->devres_lock, flags);
}

/**
 * __devres_alloc_node - Allocate device resource data
 * @release: Release function devres will be associated with
 * @size: Allocation size
 * @gfp: Allocation flags
 * @nid: NUMA node
 * @name: Name of the resource
 *
 * Allocate devres of @size bytes.  The allocated area is zeroed, then
 * associated with @release.  The returned pointer can be passed to
 * other devres_*() functions.
 *
 * RETURNS:
 * Pointer to allocated devres on success, NULL on failure.
 */
void *__devres_alloc_node(dr_release_t release, size_t size, gfp_t gfp, int nid,
              const char *name)
{
    struct devres *dr;

    dr = alloc_dr(release, size, gfp | __GFP_ZERO, nid);
    if (unlikely(!dr))
        return NULL;
    set_node_dbginfo(&dr->node, name, size);
    return dr->data;
}

/**
 * devres_release_all - Release all managed resources
 * @dev: Device to release resources for
 *
 * Release all resources associated with @dev.  This function is
 * called on driver detach.
 */
int devres_release_all(struct device *dev)
{
    unsigned long flags;
    LIST_HEAD(todo);
    int cnt;

    /* Looks like an uninitialized device structure */
    if (WARN_ON(dev->devres_head.next == NULL))
        return -ENODEV;

    /* Nothing to release if list is empty */
    if (list_empty(&dev->devres_head))
        return 0;

#if 0
    spin_lock_irqsave(&dev->devres_lock, flags);
    cnt = remove_nodes(dev, dev->devres_head.next, &dev->devres_head, &todo);
    spin_unlock_irqrestore(&dev->devres_lock, flags);

    release_nodes(dev, &todo);
#endif
    pr_notice("%s: No impl.", __func__);
    //PANIC("");
    return cnt;
}
