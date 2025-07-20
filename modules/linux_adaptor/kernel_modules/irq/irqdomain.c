#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/slab.h>
#include <linux/acpi.h>

#include "../adaptor.h"

static LIST_HEAD(irq_domain_list);
static DEFINE_MUTEX(irq_domain_mutex);

static struct irq_domain *irq_default_domain;

#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
static void debugfs_add_domain_dir(struct irq_domain *d);
static void debugfs_remove_domain_dir(struct irq_domain *d);
#else
static inline void debugfs_add_domain_dir(struct irq_domain *d) { }
static inline void debugfs_remove_domain_dir(struct irq_domain *d) { }
#endif

struct irqchip_fwid {
    struct fwnode_handle    fwnode;
    unsigned int        type;
    char            *name;
    phys_addr_t     *pa;
};

static bool irq_domain_is_nomap(struct irq_domain *domain)
{
    return IS_ENABLED(CONFIG_IRQ_DOMAIN_NOMAP) &&
           (domain->flags & IRQ_DOMAIN_FLAG_NO_MAP);
}

static void __irq_domain_publish(struct irq_domain *domain)
{
    mutex_lock(&irq_domain_mutex);
    debugfs_add_domain_dir(domain);
    list_add(&domain->link, &irq_domain_list);
    mutex_unlock(&irq_domain_mutex);

    pr_debug("Added domain %s\n", domain->name);
}

static void irq_domain_free(struct irq_domain *domain)
{
    PANIC("");
}

static void irq_domain_instantiate_descs(const struct irq_domain_info *info)
{
    if (!IS_ENABLED(CONFIG_SPARSE_IRQ))
        return;

    if (irq_alloc_descs(info->virq_base, info->virq_base, info->size,
                of_node_to_nid(to_of_node(info->fwnode))) < 0) {
        pr_info("Cannot allocate irq_descs @ IRQ%d, assuming pre-allocated\n",
            info->virq_base);
    }
}

static const char *irqchip_fwnode_get_name(const struct fwnode_handle *fwnode)
{
    struct irqchip_fwid *fwid = container_of(fwnode, struct irqchip_fwid, fwnode);

    return fwid->name;
}

const struct fwnode_operations irqchip_fwnode_ops = {
    .get_name = irqchip_fwnode_get_name,
};

#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
static void irq_domain_check_hierarchy(struct irq_domain *domain)
{
    /* Hierarchy irq_domains must implement callback alloc() */
    if (domain->ops->alloc)
        domain->flags |= IRQ_DOMAIN_FLAG_HIERARCHY;
}
#endif

static int alloc_name(struct irq_domain *domain, char *base, enum irq_domain_bus_token bus_token)
{
    if (bus_token == DOMAIN_BUS_ANY)
        domain->name = kasprintf(GFP_KERNEL, "%s", base);
    else
        domain->name = kasprintf(GFP_KERNEL, "%s-%d", base, bus_token);
    if (!domain->name)
        return -ENOMEM;

    domain->flags |= IRQ_DOMAIN_NAME_ALLOCATED;
    return 0;
}

static int alloc_fwnode_name(struct irq_domain *domain, const struct fwnode_handle *fwnode,
                 enum irq_domain_bus_token bus_token, const char *suffix)
{
    const char *sep = suffix ? "-" : "";
    const char *suf = suffix ? : "";
    char *name;

    pr_err("%s: Note: restore old NAME\n", __func__);
    if (bus_token == DOMAIN_BUS_ANY)
        //name = kasprintf(GFP_KERNEL, "%pfw%s%s", fwnode, sep, suf);
        name = kasprintf(GFP_KERNEL, "%lx%s%s", fwnode, sep, suf);
    else
        //name = kasprintf(GFP_KERNEL, "%pfw%s%s-%d", fwnode, sep, suf, bus_token);
        name = kasprintf(GFP_KERNEL, "%lx%s%s-%d", fwnode, sep, suf, bus_token);
    if (!name)
        return -ENOMEM;

    /*
     * fwnode paths contain '/', which debugfs is legitimately unhappy
     * about. Replace them with ':', which does the trick and is not as
     * offensive as '\'...
     */
    domain->name = strreplace(name, '/', ':');
    domain->flags |= IRQ_DOMAIN_NAME_ALLOCATED;
    return 0;
}

static int alloc_unknown_name(struct irq_domain *domain, enum irq_domain_bus_token bus_token)
{
    static atomic_t unknown_domains;
    int id = atomic_inc_return(&unknown_domains);

    if (bus_token == DOMAIN_BUS_ANY)
        domain->name = kasprintf(GFP_KERNEL, "unknown-%d", id);
    else
        domain->name = kasprintf(GFP_KERNEL, "unknown-%d-%d", id, bus_token);
    if (!domain->name)
        return -ENOMEM;

    domain->flags |= IRQ_DOMAIN_NAME_ALLOCATED;
    return 0;
}

static int irq_domain_set_name(struct irq_domain *domain, const struct irq_domain_info *info)
{
    enum irq_domain_bus_token bus_token = info->bus_token;
    const struct fwnode_handle *fwnode = info->fwnode;

    printk("%s: 1\n", __func__);
    if (is_fwnode_irqchip(fwnode)) {
        struct irqchip_fwid *fwid = container_of(fwnode, struct irqchip_fwid, fwnode);

        /*
         * The name_suffix is only intended to be used to avoid a name
         * collision when multiple domains are created for a single
         * device and the name is picked using a real device node.
         * (Typical use-case is regmap-IRQ controllers for devices
         * providing more than one physical IRQ.) There should be no
         * need to use name_suffix with irqchip-fwnode.
         */
        if (info->name_suffix)
            return -EINVAL;

        switch (fwid->type) {
        case IRQCHIP_FWNODE_NAMED:
        case IRQCHIP_FWNODE_NAMED_ID:
            return alloc_name(domain, fwid->name, bus_token);
        default:
            domain->name = fwid->name;
            if (bus_token != DOMAIN_BUS_ANY)
                return alloc_name(domain, fwid->name, bus_token);
        }

    } else if (is_of_node(fwnode) || is_acpi_device_node(fwnode) || is_software_node(fwnode)) {
        return alloc_fwnode_name(domain, fwnode, bus_token, info->name_suffix);
    }
    printk("%s: 2\n", __func__);

    if (domain->name)
        return 0;

    if (fwnode)
        pr_err("Invalid fwnode type for irqdomain\n");
    return alloc_unknown_name(domain, bus_token);
}

static struct irq_domain *__irq_domain_create(const struct irq_domain_info *info)
{
    struct irq_domain *domain;
    int err;

    if (WARN_ON((info->size && info->direct_max) ||
            (!IS_ENABLED(CONFIG_IRQ_DOMAIN_NOMAP) && info->direct_max) ||
            (info->direct_max && info->direct_max != info->hwirq_max)))
        return ERR_PTR(-EINVAL);

    domain = kzalloc_node(struct_size(domain, revmap, info->size),
                  GFP_KERNEL, of_node_to_nid(to_of_node(info->fwnode)));
    if (!domain)
        return ERR_PTR(-ENOMEM);

    err = irq_domain_set_name(domain, info);
    if (err) {
        kfree(domain);
        return ERR_PTR(err);
    }

    domain->fwnode = fwnode_handle_get(info->fwnode);
    fwnode_dev_initialized(domain->fwnode, true);

    /* Fill structure */
    INIT_RADIX_TREE(&domain->revmap_tree, GFP_KERNEL);
    domain->ops = info->ops;
    domain->host_data = info->host_data;
    domain->bus_token = info->bus_token;
    domain->hwirq_max = info->hwirq_max;

    if (info->direct_max)
        domain->flags |= IRQ_DOMAIN_FLAG_NO_MAP;

    domain->revmap_size = info->size;

    /*
     * Hierarchical domains use the domain lock of the root domain
     * (innermost domain).
     *
     * For non-hierarchical domains (as for root domains), the root
     * pointer is set to the domain itself so that &domain->root->mutex
     * always points to the right lock.
     */
    mutex_init(&domain->mutex);
    domain->root = domain;

    irq_domain_check_hierarchy(domain);

    return domain;
}

static struct irq_domain *__irq_domain_instantiate(const struct irq_domain_info *info,
                           bool cond_alloc_descs, bool force_associate)
{
    struct irq_domain *domain;
    int err;

    domain = __irq_domain_create(info);
    if (IS_ERR(domain))
        return domain;

    domain->flags |= info->domain_flags;
    domain->exit = info->exit;

#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
    if (info->parent) {
        domain->root = info->parent->root;
        domain->parent = info->parent;
    }
#endif

    if (info->dgc_info) {
        err = irq_domain_alloc_generic_chips(domain, info->dgc_info);
        if (err)
            goto err_domain_free;
    }

    if (info->init) {
        err = info->init(domain);
        if (err)
            goto err_domain_gc_remove;
    }

    __irq_domain_publish(domain);

    if (cond_alloc_descs && info->virq_base > 0)
        irq_domain_instantiate_descs(info);

    /*
     * Legacy interrupt domains have a fixed Linux interrupt number
     * associated. Other interrupt domains can request association by
     * providing a Linux interrupt number > 0.
     */
    if (force_associate || info->virq_base > 0) {
        irq_domain_associate_many(domain, info->virq_base, info->hwirq_base,
                      info->size - info->hwirq_base);
    }

    return domain;

err_domain_gc_remove:
    if (info->dgc_info)
        irq_domain_remove_generic_chips(domain);
err_domain_free:
    irq_domain_free(domain);
    return ERR_PTR(err);
}

static void irq_domain_set_mapping(struct irq_domain *domain,
                   irq_hw_number_t hwirq,
                   struct irq_data *irq_data)
{
    /*
     * This also makes sure that all domains point to the same root when
     * called from irq_domain_insert_irq() for each domain in a hierarchy.
     */
    lockdep_assert_held(&domain->root->mutex);

    if (irq_domain_is_nomap(domain))
        return;

    if (hwirq < domain->revmap_size)
        rcu_assign_pointer(domain->revmap[hwirq], irq_data);
    else
        radix_tree_insert(&domain->revmap_tree, hwirq, irq_data);
}

static int irq_domain_associate_locked(struct irq_domain *domain, unsigned int virq,
                       irq_hw_number_t hwirq)
{
    struct irq_data *irq_data = irq_get_irq_data(virq);
    int ret;

    if (WARN(hwirq >= domain->hwirq_max,
         "error: hwirq 0x%x is too large for %s\n", (int)hwirq, domain->name))
        return -EINVAL;
    if (WARN(!irq_data, "error: virq%i is not allocated", virq))
        return -EINVAL;
    if (WARN(irq_data->domain, "error: virq%i is already associated", virq))
        return -EINVAL;

    irq_data->hwirq = hwirq;
    irq_data->domain = domain;
    if (domain->ops->map) {
        ret = domain->ops->map(domain, virq, hwirq);
        if (ret != 0) {
            /*
             * If map() returns -EPERM, this interrupt is protected
             * by the firmware or some other service and shall not
             * be mapped. Don't bother telling the user about it.
             */
            if (ret != -EPERM) {
                pr_info("%s didn't like hwirq-0x%lx to VIRQ%i mapping (rc=%d)\n",
                       domain->name, hwirq, virq, ret);
            }
            irq_data->domain = NULL;
            irq_data->hwirq = 0;
            return ret;
        }
    }

    domain->mapcount++;
    irq_domain_set_mapping(domain, hwirq, irq_data);

    irq_clear_status_flags(virq, IRQ_NOREQUEST);

    return 0;
}

int irq_domain_associate(struct irq_domain *domain, unsigned int virq,
             irq_hw_number_t hwirq)
{
    int ret;

    mutex_lock(&domain->root->mutex);
    ret = irq_domain_associate_locked(domain, virq, hwirq);
    mutex_unlock(&domain->root->mutex);

    return ret;
}

void irq_domain_associate_many(struct irq_domain *domain, unsigned int irq_base,
                   irq_hw_number_t hwirq_base, int count)
{
    struct device_node *of_node;
    int i;

    of_node = irq_domain_get_of_node(domain);
    pr_debug("%s(%s, irqbase=%i, hwbase=%i, count=%i)\n", __func__,
        of_node_full_name(of_node), irq_base, (int)hwirq_base, count);

    for (i = 0; i < count; i++)
        irq_domain_associate(domain, irq_base + i, hwirq_base + i);
}

/**
 * irq_domain_instantiate() - Instantiate a new irq domain data structure
 * @info: Domain information pointer pointing to the information for this domain
 *
 * Return: A pointer to the instantiated irq domain or an ERR_PTR value.
 */
struct irq_domain *irq_domain_instantiate(const struct irq_domain_info *info)
{
    return __irq_domain_instantiate(info, false, false);
}

/**
 * irq_find_matching_fwspec() - Locates a domain for a given fwspec
 * @fwspec: FW specifier for an interrupt
 * @bus_token: domain-specific data
 */
struct irq_domain *irq_find_matching_fwspec(struct irq_fwspec *fwspec,
                        enum irq_domain_bus_token bus_token)
{
    pr_err("%s: fill irq_domain\n", __func__);
    static const struct irq_domain_ops dummy_ops;
    struct irq_domain *domain = kmalloc(sizeof(struct irq_domain), 0);
    /* We need to init root domain. */
    /* Refer to 'riscv_intc_init_common' in drivers/irqchip/irq-riscv-intc.c. */
    domain->ops = &dummy_ops;
    domain->hwirq_max = ~0;
    INIT_RADIX_TREE(&domain->revmap_tree, GFP_KERNEL);
    return domain;
}

static unsigned int irq_create_mapping_affinity_locked(struct irq_domain *domain,
                               irq_hw_number_t hwirq,
                               const struct irq_affinity_desc *affinity)
{
    struct device_node *of_node = irq_domain_get_of_node(domain);
    int virq;

    pr_debug("irq_create_mapping(0x%p, 0x%lx)\n", domain, hwirq);

    /* Allocate a virtual interrupt number */
    virq = irq_domain_alloc_descs(-1, 1, hwirq, of_node_to_nid(of_node),
                      affinity);
    if (virq <= 0) {
        pr_debug("-> virq allocation failed\n");
        return 0;
    }

    if (irq_domain_associate_locked(domain, virq, hwirq)) {
        irq_free_desc(virq);
        return 0;
    }

    pr_debug("irq %lu on domain %s mapped to virtual irq %u\n",
        hwirq, of_node_full_name(of_node), virq);

    return virq;
}

/**
 * irq_create_mapping_affinity() - Map a hardware interrupt into linux irq space
 * @domain: domain owning this hardware interrupt or NULL for default domain
 * @hwirq: hardware irq number in that domain space
 * @affinity: irq affinity
 *
 * Only one mapping per hardware interrupt is permitted. Returns a linux
 * irq number.
 * If the sense/trigger is to be specified, set_irq_type() should be called
 * on the number returned from that call.
 */
unsigned int irq_create_mapping_affinity(struct irq_domain *domain,
                     irq_hw_number_t hwirq,
                     const struct irq_affinity_desc *affinity)
{
    int virq;

    /* Look for default domain if necessary */
    if (domain == NULL)
        domain = irq_default_domain;
    if (domain == NULL) {
        WARN(1, "%s(, %lx) called with NULL domain\n", __func__, hwirq);
        return 0;
    }

    mutex_lock(&domain->root->mutex);

    /* Check if mapping already exists */
    virq = irq_find_mapping(domain, hwirq);
    if (virq) {
        pr_debug("existing mapping on virq %d\n", virq);
        goto out;
    }

    virq = irq_create_mapping_affinity_locked(domain, hwirq, affinity);
out:
    mutex_unlock(&domain->root->mutex);

    return virq;
}

/**
 * __irq_resolve_mapping() - Find a linux irq from a hw irq number.
 * @domain: domain owning this hardware interrupt
 * @hwirq: hardware irq number in that domain space
 * @irq: optional pointer to return the Linux irq if required
 *
 * Returns the interrupt descriptor.
 */
struct irq_desc *__irq_resolve_mapping(struct irq_domain *domain,
                       irq_hw_number_t hwirq,
                       unsigned int *irq)
{
    struct irq_desc *desc = NULL;
    struct irq_data *data;

    /* Look for default domain if necessary */
    if (domain == NULL)
        domain = irq_default_domain;
    if (domain == NULL)
        return desc;

    if (irq_domain_is_nomap(domain)) {
        if (hwirq < domain->hwirq_max) {
            data = irq_domain_get_irq_data(domain, hwirq);
            if (data && data->hwirq == hwirq)
                desc = irq_data_to_desc(data);
            if (irq && desc)
                *irq = hwirq;
        }

        return desc;
    }

    rcu_read_lock();
    /* Check if the hwirq is in the linear revmap. */
    if (hwirq < domain->revmap_size)
        data = rcu_dereference(domain->revmap[hwirq]);
    else
        data = radix_tree_lookup(&domain->revmap_tree, hwirq);

    if (likely(data)) {
        desc = irq_data_to_desc(data);
        if (irq)
            *irq = data->irq;
    }

    rcu_read_unlock();
    return desc;
}

int irq_domain_alloc_descs(int virq, unsigned int cnt, irq_hw_number_t hwirq,
               int node, const struct irq_affinity_desc *affinity)
{
    unsigned int hint;

    if (virq >= 0) {
        virq = __irq_alloc_descs(virq, virq, cnt, node, THIS_MODULE,
                     affinity);
    } else {
        hint = hwirq % nr_irqs;
        if (hint == 0)
            hint++;
        virq = __irq_alloc_descs(-1, hint, cnt, node, THIS_MODULE,
                     affinity);
        if (virq <= 0 && hint > 1) {
            virq = __irq_alloc_descs(-1, 1, cnt, node, THIS_MODULE,
                         affinity);
        }
    }

    return virq;
}
