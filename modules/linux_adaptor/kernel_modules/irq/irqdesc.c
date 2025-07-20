#include <linux/irq.h>
#include <linux/irqdomain.h>

#include "internals.h"
#include "../adaptor.h"

/*
 * lockdep: we want to handle all irq_desc locks as a single lock-class:
 */
static struct lock_class_key irq_desc_lock_class;

static DEFINE_MUTEX(sparse_irq_lock);

int nr_irqs = NR_IRQS;
static struct maple_tree sparse_irqs = MTREE_INIT_EXT(sparse_irqs,
                    MT_FLAGS_ALLOC_RANGE |
                    MT_FLAGS_LOCK_EXTERN |
                    MT_FLAGS_USE_RCU,
                    sparse_irq_lock);

#ifdef CONFIG_SPARSE_IRQ
static const struct kobj_type irq_kobj_type;
#endif

static void desc_smp_init(struct irq_desc *desc, int node,
              const struct cpumask *affinity)
{
    if (!affinity)
        affinity = irq_default_affinity;
    cpumask_copy(desc->irq_common_data.affinity, affinity);

#ifdef CONFIG_GENERIC_PENDING_IRQ
    cpumask_clear(desc->pending_mask);
#endif
#ifdef CONFIG_NUMA
    desc->irq_common_data.node = node;
#endif
}

static void desc_set_defaults(unsigned int irq, struct irq_desc *desc, int node,
                  const struct cpumask *affinity, struct module *owner)
{
    int cpu;

    desc->irq_common_data.handler_data = NULL;
    desc->irq_common_data.msi_desc = NULL;

    desc->irq_data.common = &desc->irq_common_data;
    desc->irq_data.irq = irq;
    desc->irq_data.chip = &no_irq_chip;
    desc->irq_data.chip_data = NULL;
    irq_settings_clr_and_set(desc, ~0, _IRQ_DEFAULT_INIT_FLAGS);
    irqd_set(&desc->irq_data, IRQD_IRQ_DISABLED);
    irqd_set(&desc->irq_data, IRQD_IRQ_MASKED);
    desc->handle_irq = handle_bad_irq;
    desc->depth = 1;
    desc->irq_count = 0;
    desc->irqs_unhandled = 0;
    desc->tot_count = 0;
    desc->name = NULL;
    desc->owner = owner;
    pr_err("%s: No [percpu] desc->kstat_irqs\n", __func__);
    /*
    for_each_possible_cpu(cpu)
        *per_cpu_ptr(desc->kstat_irqs, cpu) = (struct irqstat) { };
        */
    desc_smp_init(desc, node, affinity);
}

static int alloc_masks(struct irq_desc *desc, int node)
{
    if (!zalloc_cpumask_var_node(&desc->irq_common_data.affinity,
                     GFP_KERNEL, node))
        return -ENOMEM;

#ifdef CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK
    if (!zalloc_cpumask_var_node(&desc->irq_common_data.effective_affinity,
                     GFP_KERNEL, node)) {
        free_cpumask_var(desc->irq_common_data.affinity);
        return -ENOMEM;
    }
#endif

#ifdef CONFIG_GENERIC_PENDING_IRQ
    if (!zalloc_cpumask_var_node(&desc->pending_mask, GFP_KERNEL, node)) {
#ifdef CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK
        free_cpumask_var(desc->irq_common_data.effective_affinity);
#endif
        free_cpumask_var(desc->irq_common_data.affinity);
        return -ENOMEM;
    }
#endif
    return 0;
}

static int init_desc(struct irq_desc *desc, int irq, int node,
             unsigned int flags,
             const struct cpumask *affinity,
             struct module *owner)
{
    pr_err("%s: No [percpu] desc->kstat_irqs\n", __func__);
    /*
    desc->kstat_irqs = alloc_percpu(struct irqstat);
    if (!desc->kstat_irqs)
        return -ENOMEM;
        */

    if (alloc_masks(desc, node)) {
        //free_percpu(desc->kstat_irqs);
        return -ENOMEM;
    }

    raw_spin_lock_init(&desc->lock);
    lockdep_set_class(&desc->lock, &irq_desc_lock_class);
    mutex_init(&desc->request_mutex);
    init_waitqueue_head(&desc->wait_for_threads);
    desc_set_defaults(irq, desc, node, affinity, owner);
    irqd_set(&desc->irq_data, flags);
    irq_resend_init(desc);
#ifdef CONFIG_SPARSE_IRQ
    kobject_init(&desc->kobj, &irq_kobj_type);
    init_rcu_head(&desc->rcu);
#endif

    return 0;
}

static struct irq_desc *alloc_desc(int irq, int node, unsigned int flags,
                   const struct cpumask *affinity,
                   struct module *owner)
{
    struct irq_desc *desc;
    int ret;

    desc = kzalloc_node(sizeof(*desc), GFP_KERNEL, node);
    if (!desc)
        return NULL;

    ret = init_desc(desc, irq, node, flags, affinity, owner);
    if (unlikely(ret)) {
        kfree(desc);
        return NULL;
    }

    return desc;
}

static void irq_insert_desc(unsigned int irq, struct irq_desc *desc)
{
    MA_STATE(mas, &sparse_irqs, irq, irq);
    WARN_ON(mas_store_gfp(&mas, desc, GFP_KERNEL) != 0);
}

#ifdef CONFIG_SYSFS
static void irq_sysfs_add(int irq, struct irq_desc *desc)
{
    pr_err("%s: No impl.", __func__);
}
#endif /* CONFIG_SYSFS */

#ifdef CONFIG_SPARSE_IRQ
static void free_desc(unsigned int irq)
{
    PANIC("");
}

static int alloc_descs(unsigned int start, unsigned int cnt, int node,
               const struct irq_affinity_desc *affinity,
               struct module *owner)
{
    struct irq_desc *desc;
    int i;

    /* Validate affinity mask(s) */
    if (affinity) {
        for (i = 0; i < cnt; i++) {
            if (cpumask_empty(&affinity[i].mask))
                return -EINVAL;
        }
    }

    for (i = 0; i < cnt; i++) {
        const struct cpumask *mask = NULL;
        unsigned int flags = 0;

        if (affinity) {
            if (affinity->is_managed) {
                flags = IRQD_AFFINITY_MANAGED |
                    IRQD_MANAGED_SHUTDOWN;
            }
            flags |= IRQD_AFFINITY_SET;
            mask = &affinity->mask;
            node = cpu_to_node(cpumask_first(mask));
            affinity++;
        }

        desc = alloc_desc(start + i, node, flags, mask, owner);
        if (!desc)
            goto err;
        irq_insert_desc(start + i, desc);
        irq_sysfs_add(start + i, desc);
        irq_add_debugfs_entry(start + i, desc);
    }
    return start;

err:
    for (i--; i >= 0; i--)
        free_desc(start + i);
    return -ENOMEM;
}
#else /* CONFIG_SPARSE_IRQ */
#warn "No CONFIG_SPARSE_IRQ"
#endif /* CONFIG_SPARSE_IRQ */

static int irq_find_free_area(unsigned int from, unsigned int cnt)
{
    MA_STATE(mas, &sparse_irqs, 0, 0);

    if (mas_empty_area(&mas, from, MAX_SPARSE_IRQS, cnt))
        return -ENOSPC;
    return mas.index;
}

static int irq_expand_nr_irqs(unsigned int nr)
{
    if (nr > MAX_SPARSE_IRQS)
        return -ENOMEM;
    nr_irqs = nr;
    return 0;
}

/**
 * __irq_alloc_descs - allocate and initialize a range of irq descriptors
 * @irq:    Allocate for specific irq number if irq >= 0
 * @from:   Start the search from this irq number
 * @cnt:    Number of consecutive irqs to allocate.
 * @node:   Preferred node on which the irq descriptor should be allocated
 * @owner:  Owning module (can be NULL)
 * @affinity:   Optional pointer to an affinity mask array of size @cnt which
 *      hints where the irq descriptors should be allocated and which
 *      default affinities to use
 *
 * Returns the first irq number or error code
 */
int __ref
__irq_alloc_descs(int irq, unsigned int from, unsigned int cnt, int node,
          struct module *owner, const struct irq_affinity_desc *affinity)
{
    int start, ret;

    printk("%s: 1\n", __func__);
    if (!cnt)
        return -EINVAL;

    if (irq >= 0) {
        if (from > irq)
            return -EINVAL;
        from = irq;
    } else {
        /*
         * For interrupts which are freely allocated the
         * architecture can force a lower bound to the @from
         * argument. x86 uses this to exclude the GSI space.
         */
        from = arch_dynirq_lower_bound(from);
    }

    mutex_lock(&sparse_irq_lock);

    start = irq_find_free_area(from, cnt);
    ret = -EEXIST;
    if (irq >=0 && start != irq)
        goto unlock;

    if (start + cnt > nr_irqs) {
        ret = irq_expand_nr_irqs(start + cnt);
        if (ret)
            goto unlock;
    }
    ret = alloc_descs(start, cnt, node, affinity, owner);
unlock:
    mutex_unlock(&sparse_irq_lock);
    return ret;
}

struct irq_desc *irq_to_desc(unsigned int irq)
{
    return mtree_load(&sparse_irqs, irq);
}

struct irq_desc *
__irq_get_desc_lock(unsigned int irq, unsigned long *flags, bool bus,
            unsigned int check)
{
    struct irq_desc *desc = irq_to_desc(irq);

    if (desc) {
        if (check & _IRQ_DESC_CHECK) {
            if ((check & _IRQ_DESC_PERCPU) &&
                !irq_settings_is_per_cpu_devid(desc))
                return NULL;

            if (!(check & _IRQ_DESC_PERCPU) &&
                irq_settings_is_per_cpu_devid(desc))
                return NULL;
        }

        if (bus)
            chip_bus_lock(desc);
        raw_spin_lock_irqsave(&desc->lock, *flags);
    }
    return desc;
}

void __irq_put_desc_unlock(struct irq_desc *desc, unsigned long flags, bool bus)
    __releases(&desc->lock)
{
    raw_spin_unlock_irqrestore(&desc->lock, flags);
    if (bus)
        chip_bus_sync_unlock(desc);
}
