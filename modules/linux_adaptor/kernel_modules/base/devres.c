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

static void devm_percpu_release(struct device *dev, void *pdata)
{
    void __percpu *p;

    p = *(void __percpu **)pdata;
    free_percpu(p);
}

static struct devres *find_dr(struct device *dev, dr_release_t release,
                  dr_match_t match, void *match_data)
{
    struct devres_node *node;

    list_for_each_entry_reverse(node, &dev->devres_head, entry) {
        struct devres *dr = container_of(node, struct devres, node);

        if (node->release != release)
            continue;
        if (match && !match(dev, dr->data, match_data))
            continue;
        return dr;
    }

    return NULL;
}

/**
 * __devm_alloc_percpu - Resource-managed alloc_percpu
 * @dev: Device to allocate per-cpu memory for
 * @size: Size of per-cpu memory to allocate
 * @align: Alignment of per-cpu memory to allocate
 *
 * Managed alloc_percpu. Per-cpu memory allocated with this function is
 * automatically freed on driver detach.
 *
 * RETURNS:
 * Pointer to allocated memory on success, NULL on failure.
 */
void __percpu *__devm_alloc_percpu(struct device *dev, size_t size,
        size_t align)
{
    void *p;
    void __percpu *pcpu;

    pcpu = __alloc_percpu(size, align);
    if (!pcpu)
        return NULL;

    p = devres_alloc(devm_percpu_release, sizeof(void *), GFP_KERNEL);
    if (!p) {
        free_percpu(pcpu);
        return NULL;
    }

    *(void __percpu **)p = pcpu;

    devres_add(dev, p);

    return pcpu;
}

/**
 * devres_remove - Find a device resource and remove it
 * @dev: Device to find resource from
 * @release: Look for resources associated with this release function
 * @match: Match function (optional)
 * @match_data: Data for the match function
 *
 * Find the latest devres of @dev associated with @release and for
 * which @match returns 1.  If @match is NULL, it's considered to
 * match all.  If found, the resource is removed atomically and
 * returned.
 *
 * RETURNS:
 * Pointer to removed devres on success, NULL if not found.
 */
void *devres_remove(struct device *dev, dr_release_t release,
            dr_match_t match, void *match_data)
{
    struct devres *dr;
    unsigned long flags;

    spin_lock_irqsave(&dev->devres_lock, flags);
    dr = find_dr(dev, release, match, match_data);
    if (dr) {
        list_del_init(&dr->node.entry);
        devres_log(dev, &dr->node, "REM");
    }
    spin_unlock_irqrestore(&dev->devres_lock, flags);

    if (dr)
        return dr->data;
    return NULL;
}

/**
 * devres_release - Find a device resource and destroy it, calling release
 * @dev: Device to find resource from
 * @release: Look for resources associated with this release function
 * @match: Match function (optional)
 * @match_data: Data for the match function
 *
 * Find the latest devres of @dev associated with @release and for
 * which @match returns 1.  If @match is NULL, it's considered to
 * match all.  If found, the resource is removed atomically, the
 * release function called and the resource freed.
 *
 * RETURNS:
 * 0 if devres is found and freed, -ENOENT if not found.
 */
int devres_release(struct device *dev, dr_release_t release,
           dr_match_t match, void *match_data)
{
    void *res;

    res = devres_remove(dev, release, match, match_data);
    if (unlikely(!res))
        return -ENOENT;

    (*release)(dev, res);
    devres_free(res);
    return 0;
}

/**
 * devm_kmemdup - Resource-managed kmemdup
 * @dev: Device this memory belongs to
 * @src: Memory region to duplicate
 * @len: Memory region length
 * @gfp: GFP mask to use
 *
 * Duplicate region of a memory using resource managed kmalloc
 */
void *devm_kmemdup(struct device *dev, const void *src, size_t len, gfp_t gfp)
{
    void *p;

    p = devm_kmalloc(dev, len, gfp);
    if (p)
        memcpy(p, src, len);

    return p;
}

/**
 * devm_krealloc - Resource-managed krealloc()
 * @dev: Device to re-allocate memory for
 * @ptr: Pointer to the memory chunk to re-allocate
 * @new_size: New allocation size
 * @gfp: Allocation gfp flags
 *
 * Managed krealloc(). Resizes the memory chunk allocated with devm_kmalloc().
 * Behaves similarly to regular krealloc(): if @ptr is NULL or ZERO_SIZE_PTR,
 * it's the equivalent of devm_kmalloc(). If new_size is zero, it frees the
 * previously allocated memory and returns ZERO_SIZE_PTR. This function doesn't
 * change the order in which the release callback for the re-alloc'ed devres
 * will be called (except when falling back to devm_kmalloc() or when freeing
 * resources when new_size is zero). The contents of the memory are preserved
 * up to the lesser of new and old sizes.
 */
void *devm_krealloc(struct device *dev, void *ptr, size_t new_size, gfp_t gfp)
{
    size_t total_new_size, total_old_size;
    struct devres *old_dr, *new_dr;
    unsigned long flags;

    if (unlikely(!new_size)) {
        devm_kfree(dev, ptr);
        return ZERO_SIZE_PTR;
    }

#if 0
    if (unlikely(ZERO_OR_NULL_PTR(ptr)))
        return devm_kmalloc(dev, new_size, gfp);

    if (WARN_ON(is_kernel_rodata((unsigned long)ptr)))
        /*
         * We cannot reliably realloc a const string returned by
         * devm_kstrdup_const().
         */
        return NULL;

    if (!check_dr_size(new_size, &total_new_size))
        return NULL;

    total_old_size = ksize(container_of(ptr, struct devres, data));
    if (total_old_size == 0) {
        WARN(1, "Pointer doesn't point to dynamically allocated memory.");
        return NULL;
    }

    /*
     * If new size is smaller or equal to the actual number of bytes
     * allocated previously - just return the same pointer.
     */
    if (total_new_size <= total_old_size)
        return ptr;

    /*
     * Otherwise: allocate new, larger chunk. We need to allocate before
     * taking the lock as most probably the caller uses GFP_KERNEL.
     * alloc_dr() will call check_dr_size() to reserve extra memory
     * for struct devres automatically, so size @new_size user request
     * is delivered to it directly as devm_kmalloc() does.
     */
    new_dr = alloc_dr(devm_kmalloc_release,
              new_size, gfp, dev_to_node(dev));
    if (!new_dr)
        return NULL;

    /*
     * The spinlock protects the linked list against concurrent
     * modifications but not the resource itself.
     */
    spin_lock_irqsave(&dev->devres_lock, flags);

    old_dr = find_dr(dev, devm_kmalloc_release, devm_kmalloc_match, ptr);
    if (!old_dr) {
        spin_unlock_irqrestore(&dev->devres_lock, flags);
        kfree(new_dr);
        WARN(1, "Memory chunk not managed or managed by a different device.");
        return NULL;
    }

    replace_dr(dev, &old_dr->node, &new_dr->node);

    spin_unlock_irqrestore(&dev->devres_lock, flags);

    /*
     * We can copy the memory contents after releasing the lock as we're
     * no longer modifying the list links.
     */
    memcpy(new_dr->data, old_dr->data,
           total_old_size - offsetof(struct devres, data));
    /*
     * Same for releasing the old devres - it's now been removed from the
     * list. This is also the reason why we must not use devm_kfree() - the
     * links are no longer valid.
     */
    kfree(old_dr);
#endif

    PANIC("");
    return new_dr->data;
}
