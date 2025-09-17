#include <linux/mm.h>
#include <linux/device.h>
#include <linux/resource_ext.h>
#include <asm/io.h>

#include "../adaptor.h"

struct resource ioport_resource = {
    .name   = "PCI IO",
    .start  = 0,
    .end    = IO_SPACE_LIMIT,
    .flags  = IORESOURCE_IO,
};

struct resource iomem_resource = {
    .name   = "PCI mem",
    .start  = 0,
    .end    = -1,
    .flags  = IORESOURCE_MEM,
};

static DEFINE_RWLOCK(resource_lock);
static DECLARE_WAIT_QUEUE_HEAD(muxed_resource_wait);

struct region_devres {
    struct resource *parent;
    resource_size_t start;
    resource_size_t n;
};

static void devm_region_release(struct device *dev, void *res)
{
    struct region_devres *this = res;

    __release_region(this->parent, this->start, this->n);
}

struct resource *
__devm_request_region(struct device *dev, struct resource *parent,
              resource_size_t start, resource_size_t n, const char *name)
{
    struct region_devres *dr = NULL;
    struct resource *res;

    dr = devres_alloc(devm_region_release, sizeof(struct region_devres),
              GFP_KERNEL);
    if (!dr)
        return NULL;

    dr->parent = parent;
    dr->start = start;
    dr->n = n;

    res = __request_region(parent, start, n, name, 0);
    if (res)
        devres_add(dev, dr);
    else
        devres_free(dr);

    return res;
}

static struct resource *alloc_resource(gfp_t flags)
{
    return kzalloc(sizeof(struct resource), flags);
}

/* Return the conflict entry if you can't request it */
static struct resource * __request_resource(struct resource *root, struct resource *new)
{
    resource_size_t start = new->start;
    resource_size_t end = new->end;
    struct resource *tmp, **p;

    if (end < start)
        return root;
    if (start < root->start)
        return root;
    if (end > root->end)
        return root;
    p = &root->child;
    for (;;) {
        tmp = *p;
        if (!tmp || tmp->start > end) {
            new->sibling = tmp;
            *p = new;
            new->parent = root;
            return NULL;
        }
        p = &tmp->sibling;
        if (tmp->end < start)
            continue;
        return tmp;
    }
}

static int __request_region_locked(struct resource *res, struct resource *parent,
                   resource_size_t start, resource_size_t n,
                   const char *name, int flags)
{
    DECLARE_WAITQUEUE(wait, current);

    res->name = name;
    res->start = start;
    res->end = start + n - 1;

    for (;;) {
        struct resource *conflict;

        res->flags = resource_type(parent) | resource_ext_type(parent);
        res->flags |= IORESOURCE_BUSY | flags;
        res->desc = parent->desc;

        conflict = __request_resource(parent, res);
        if (!conflict)
            break;
        /*
         * mm/hmm.c reserves physical addresses which then
         * become unavailable to other users.  Conflicts are
         * not expected.  Warn to aid debugging if encountered.
         */
        if (conflict->desc == IORES_DESC_DEVICE_PRIVATE_MEMORY) {
            pr_warn("Unaddressable device %s %pR conflicts with %pR",
                conflict->name, conflict, res);
        }
        if (conflict != parent) {
            if (!(conflict->flags & IORESOURCE_BUSY)) {
                parent = conflict;
                continue;
            }
        }
        if (conflict->flags & flags & IORESOURCE_MUXED) {
            add_wait_queue(&muxed_resource_wait, &wait);
            write_unlock(&resource_lock);
            set_current_state(TASK_UNINTERRUPTIBLE);
            schedule();
            remove_wait_queue(&muxed_resource_wait, &wait);
            write_lock(&resource_lock);
            continue;
        }
        /* Uhhuh, that didn't work out.. */
        return -EBUSY;
    }

    return 0;
}

static void free_resource(struct resource *res)
{
    /**
     * If the resource was allocated using memblock early during boot
     * we'll leak it here: we can only return full pages back to the
     * buddy and trying to be smart and reusing them eventually in
     * alloc_resource() overcomplicates resource handling.
     */
    if (res && PageSlab(virt_to_head_page(res)))
        kfree(res);
}

static void revoke_iomem(struct resource *res) {}

/**
 * __request_region - create a new busy resource region
 * @parent: parent resource descriptor
 * @start: resource start address
 * @n: resource region size
 * @name: reserving caller's ID string
 * @flags: IO resource flags
 */
struct resource *__request_region(struct resource *parent,
                  resource_size_t start, resource_size_t n,
                  const char *name, int flags)
{
    struct resource *res = alloc_resource(GFP_KERNEL);
    int ret;

    if (!res)
        return NULL;

    write_lock(&resource_lock);
    ret = __request_region_locked(res, parent, start, n, name, flags);
    write_unlock(&resource_lock);

    if (ret) {
        free_resource(res);
        return NULL;
    }

    if (parent == &iomem_resource)
        revoke_iomem(res);

    return res;
}

/**
 * __release_region - release a previously reserved resource region
 * @parent: parent resource descriptor
 * @start: resource start address
 * @n: resource region size
 *
 * The described resource region must match a currently busy region.
 */
void __release_region(struct resource *parent, resource_size_t start,
              resource_size_t n)
{
    PANIC("");
}

struct resource_entry *resource_list_create_entry(struct resource *res,
                          size_t extra_size)
{
    struct resource_entry *entry;

    entry = kzalloc(sizeof(*entry) + extra_size, GFP_KERNEL);
    if (entry) {
        INIT_LIST_HEAD(&entry->node);
        entry->res = res ? res : &entry->__res;
    }

    return entry;
}

/*
 * Managed region resource
 */
static void devm_resource_release(struct device *dev, void *ptr)
{
    struct resource **r = ptr;

    release_resource(*r);
}

/**
 * devm_request_resource() - request and reserve an I/O or memory resource
 * @dev: device for which to request the resource
 * @root: root of the resource tree from which to request the resource
 * @new: descriptor of the resource to request
 *
 * This is a device-managed version of request_resource(). There is usually
 * no need to release resources requested by this function explicitly since
 * that will be taken care of when the device is unbound from its driver.
 * If for some reason the resource needs to be released explicitly, because
 * of ordering issues for example, drivers must call devm_release_resource()
 * rather than the regular release_resource().
 *
 * When a conflict is detected between any existing resources and the newly
 * requested resource, an error message will be printed.
 *
 * Returns 0 on success or a negative error code on failure.
 */
int devm_request_resource(struct device *dev, struct resource *root,
              struct resource *new)
{
    struct resource *conflict, **ptr;

    ptr = devres_alloc(devm_resource_release, sizeof(*ptr), GFP_KERNEL);
    if (!ptr)
        return -ENOMEM;

    *ptr = new;

    conflict = request_resource_conflict(root, new);
    if (conflict) {
    printk("%s: step2 dev(%lx) conflict(%lx)\n", __func__, dev, conflict->name);
        dev_err(dev, "resource collision: %pR conflicts with %s %pR\n",
            new, conflict->name, conflict);
        devres_free(ptr);
        return -EBUSY;
    }

    devres_add(dev, ptr);
    return 0;
}

/**
 * request_resource_conflict - request and reserve an I/O or memory resource
 * @root: root resource descriptor
 * @new: resource descriptor desired by caller
 *
 * Returns 0 for success, conflict resource on error.
 */
struct resource *request_resource_conflict(struct resource *root, struct resource *new)
{
    struct resource *conflict;

    write_lock(&resource_lock);
    conflict = __request_resource(root, new);
    write_unlock(&resource_lock);
    return conflict;
}

/**
 * resource_alignment - calculate resource's alignment
 * @res: resource pointer
 *
 * Returns alignment on success, 0 (invalid alignment) on failure.
 */
resource_size_t resource_alignment(struct resource *res)
{
    switch (res->flags & (IORESOURCE_SIZEALIGN | IORESOURCE_STARTALIGN)) {
    case IORESOURCE_SIZEALIGN:
        return resource_size(res);
    case IORESOURCE_STARTALIGN:
        return res->start;
    default:
        return 0;
    }
}

void __weak arch_remove_reservations(struct resource *avail)
{
}

static void resource_clip(struct resource *res, resource_size_t min,
              resource_size_t max)
{
    if (res->start < min)
        res->start = min;
    if (res->end > max)
        res->end = max;
}

/*
 * Find empty space in the resource tree with the given range and
 * alignment constraints
 */
static int __find_resource_space(struct resource *root, struct resource *old,
                 struct resource *new, resource_size_t size,
                 struct resource_constraint *constraint)
{
    struct resource *this = root->child;
    struct resource tmp = *new, avail, alloc;
    resource_alignf alignf = constraint->alignf;

    tmp.start = root->start;
    /*
     * Skip past an allocated resource that starts at 0, since the assignment
     * of this->start - 1 to tmp->end below would cause an underflow.
     */
    if (this && this->start == root->start) {
        tmp.start = (this == old) ? old->start : this->end + 1;
        this = this->sibling;
    }
    for(;;) {
        if (this)
            tmp.end = (this == old) ?  this->end : this->start - 1;
        else
            tmp.end = root->end;

        if (tmp.end < tmp.start)
            goto next;

        resource_clip(&tmp, constraint->min, constraint->max);
        arch_remove_reservations(&tmp);

        /* Check for overflow after ALIGN() */
        avail.start = ALIGN(tmp.start, constraint->align);
        avail.end = tmp.end;
        avail.flags = new->flags & ~IORESOURCE_UNSET;
        if (avail.start >= tmp.start) {
            alloc.flags = avail.flags;
            if (alignf) {
                alloc.start = alignf(constraint->alignf_data,
                             &avail, size, constraint->align);
            } else {
                alloc.start = avail.start;
            }
            alloc.end = alloc.start + size - 1;
            if (alloc.start <= alloc.end &&
                resource_contains(&avail, &alloc)) {
                new->start = alloc.start;
                new->end = alloc.end;
                return 0;
            }
        }

next:       if (!this || this->end == root->end)
            break;

        if (this != old)
            tmp.start = this->end + 1;
        this = this->sibling;
    }
    return -EBUSY;
}

static int __release_resource(struct resource *old, bool release_child)
{
    PANIC("");
}

/**
 * reallocate_resource - allocate a slot in the resource tree given range & alignment.
 *  The resource will be relocated if the new size cannot be reallocated in the
 *  current location.
 *
 * @root: root resource descriptor
 * @old:  resource descriptor desired by caller
 * @newsize: new size of the resource descriptor
 * @constraint: the size and alignment constraints to be met.
 */
static int reallocate_resource(struct resource *root, struct resource *old,
                   resource_size_t newsize,
                   struct resource_constraint *constraint)
{
    int err=0;
    struct resource new = *old;
    struct resource *conflict;

    write_lock(&resource_lock);

    if ((err = __find_resource_space(root, old, &new, newsize, constraint)))
        goto out;

    if (resource_contains(&new, old)) {
        old->start = new.start;
        old->end = new.end;
        goto out;
    }

    if (old->child) {
        err = -EBUSY;
        goto out;
    }

    if (resource_contains(old, &new)) {
        old->start = new.start;
        old->end = new.end;
    } else {
        __release_resource(old, true);
        *old = new;
        conflict = __request_resource(root, old);
        BUG_ON(conflict);
    }
out:
    write_unlock(&resource_lock);
    return err;
}

/**
 * allocate_resource - allocate empty slot in the resource tree given range & alignment.
 *  The resource will be reallocated with a new size if it was already allocated
 * @root: root resource descriptor
 * @new: resource descriptor desired by caller
 * @size: requested resource region size
 * @min: minimum boundary to allocate
 * @max: maximum boundary to allocate
 * @align: alignment requested, in bytes
 * @alignf: alignment function, optional, called if not NULL
 * @alignf_data: arbitrary data to pass to the @alignf function
 */
int allocate_resource(struct resource *root, struct resource *new,
              resource_size_t size, resource_size_t min,
              resource_size_t max, resource_size_t align,
              resource_alignf alignf,
              void *alignf_data)
{
    int err;
    struct resource_constraint constraint;

    constraint.min = min;
    constraint.max = max;
    constraint.align = align;
    constraint.alignf = alignf;
    constraint.alignf_data = alignf_data;

    if ( new->parent ) {
        /* resource is already allocated, try reallocating with
           the new constraints */
        return reallocate_resource(root, new, size, &constraint);
    }

    write_lock(&resource_lock);
    err = find_resource_space(root, new, size, &constraint);
    if (err >= 0 && __request_resource(root, new))
        err = -EBUSY;
    write_unlock(&resource_lock);
    return err;
}

/**
 * find_resource_space - Find empty space in the resource tree
 * @root:   Root resource descriptor
 * @new:    Resource descriptor awaiting an empty resource space
 * @size:   The minimum size of the empty space
 * @constraint: The range and alignment constraints to be met
 *
 * Finds an empty space under @root in the resource tree satisfying range and
 * alignment @constraints.
 *
 * Return:
 * * %0     - if successful, @new members start, end, and flags are altered.
 * * %-EBUSY    - if no empty space was found.
 */
int find_resource_space(struct resource *root, struct resource *new,
            resource_size_t size,
            struct resource_constraint *constraint)
{
    return  __find_resource_space(root, NULL, new, size, constraint);
}
