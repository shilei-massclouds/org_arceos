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

static int irq_domain_translate(struct irq_domain *d,
                struct irq_fwspec *fwspec,
                irq_hw_number_t *hwirq, unsigned int *type)
{
#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
    if (d->ops->translate)
        return d->ops->translate(d, fwspec, hwirq, type);
#endif
    if (d->ops->xlate)
        return d->ops->xlate(d, to_of_node(fwspec->fwnode),
                     fwspec->param, fwspec->param_count,
                     hwirq, type);

    /* If domain has no translation, then we assume interrupt line */
    *hwirq = fwspec->param[0];
    return 0;
}

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

    pr_notice("%s: Note: restore old NAME\n", __func__);
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
    struct irq_domain *h, *found = NULL;
    struct fwnode_handle *fwnode = fwspec->fwnode;
    int rc;

    /*
     * We might want to match the legacy controller last since
     * it might potentially be set to match all interrupts in
     * the absence of a device node. This isn't a problem so far
     * yet though...
     *
     * bus_token == DOMAIN_BUS_ANY matches any domain, any other
     * values must generate an exact match for the domain to be
     * selected.
     */
    mutex_lock(&irq_domain_mutex);
    list_for_each_entry(h, &irq_domain_list, link) {
        if (h->ops->select && bus_token != DOMAIN_BUS_ANY)
            rc = h->ops->select(h, fwspec, bus_token);
        else if (h->ops->match)
            rc = h->ops->match(h, to_of_node(fwnode), bus_token);
        else
            rc = ((fwnode != NULL) && (h->fwnode == fwnode) &&
                  ((bus_token == DOMAIN_BUS_ANY) ||
                   (h->bus_token == bus_token)));

        if (rc) {
            found = h;
            break;
        }
    }
    mutex_unlock(&irq_domain_mutex);
    return found;
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

#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
/**
 * irq_domain_get_irq_data - Get irq_data associated with @virq and @domain
 * @domain: domain to match
 * @virq:   IRQ number to get irq_data
 */
struct irq_data *irq_domain_get_irq_data(struct irq_domain *domain,
                     unsigned int virq)
{
    struct irq_data *irq_data;

    for (irq_data = irq_get_irq_data(virq); irq_data;
         irq_data = irq_data->parent_data)
        if (irq_data->domain == domain)
            return irq_data;

    return NULL;
}

/**
 * irq_domain_set_hwirq_and_chip - Set hwirq and irqchip of @virq at @domain
 * @domain: Interrupt domain to match
 * @virq:   IRQ number
 * @hwirq:  The hwirq number
 * @chip:   The associated interrupt chip
 * @chip_data:  The associated chip data
 */
int irq_domain_set_hwirq_and_chip(struct irq_domain *domain, unsigned int virq,
                  irq_hw_number_t hwirq,
                  const struct irq_chip *chip,
                  void *chip_data)
{
    struct irq_data *irq_data = irq_domain_get_irq_data(domain, virq);

    if (!irq_data)
        return -ENOENT;

    irq_data->hwirq = hwirq;
    irq_data->chip = (struct irq_chip *)(chip ? chip : &no_irq_chip);
    irq_data->chip_data = chip_data;

    return 0;
}

/**
 * irq_domain_set_info - Set the complete data for a @virq in @domain
 * @domain:     Interrupt domain to match
 * @virq:       IRQ number
 * @hwirq:      The hardware interrupt number
 * @chip:       The associated interrupt chip
 * @chip_data:      The associated interrupt chip data
 * @handler:        The interrupt flow handler
 * @handler_data:   The interrupt flow handler data
 * @handler_name:   The interrupt handler name
 */
void irq_domain_set_info(struct irq_domain *domain, unsigned int virq,
             irq_hw_number_t hwirq, const struct irq_chip *chip,
             void *chip_data, irq_flow_handler_t handler,
             void *handler_data, const char *handler_name)
{
    irq_domain_set_hwirq_and_chip(domain, virq, hwirq, chip, chip_data);
    __irq_set_handler(virq, handler, 0, handler_name);
    irq_set_handler_data(virq, handler_data);
}
#endif

unsigned int irq_create_of_mapping(struct of_phandle_args *irq_data)
{
    struct irq_fwspec fwspec;

    of_phandle_args_to_fwspec(irq_data->np, irq_data->args,
                  irq_data->args_count, &fwspec);

    return irq_create_fwspec_mapping(&fwspec);
}

void of_phandle_args_to_fwspec(struct device_node *np, const u32 *args,
                   unsigned int count, struct irq_fwspec *fwspec)
{
    int i;

    fwspec->fwnode = of_node_to_fwnode(np);
    fwspec->param_count = count;

    for (i = 0; i < count; i++)
        fwspec->param[i] = args[i];
}
static struct irq_data *irq_domain_insert_irq_data(struct irq_domain *domain,
                           struct irq_data *child)
{
    struct irq_data *irq_data;

    irq_data = kzalloc_node(sizeof(*irq_data), GFP_KERNEL,
                irq_data_get_node(child));
    if (irq_data) {
        child->parent_data = irq_data;
        irq_data->irq = child->irq;
        irq_data->common = child->common;
        irq_data->domain = domain;
    }

    return irq_data;
}

static void __irq_domain_free_hierarchy(struct irq_data *irq_data)
{
    struct irq_data *tmp;

    while (irq_data) {
        tmp = irq_data;
        irq_data = irq_data->parent_data;
        kfree(tmp);
    }
}

static void irq_domain_free_irq_data(unsigned int virq, unsigned int nr_irqs)
{
    struct irq_data *irq_data, *tmp;
    int i;

    for (i = 0; i < nr_irqs; i++) {
        irq_data = irq_get_irq_data(virq + i);
        tmp = irq_data->parent_data;
        irq_data->parent_data = NULL;
        irq_data->domain = NULL;

        __irq_domain_free_hierarchy(tmp);
    }
}

static int irq_domain_alloc_irq_data(struct irq_domain *domain,
                     unsigned int virq, unsigned int nr_irqs)
{
    struct irq_data *irq_data;
    struct irq_domain *parent;
    int i;

    /* The outermost irq_data is embedded in struct irq_desc */
    for (i = 0; i < nr_irqs; i++) {
        irq_data = irq_get_irq_data(virq + i);
        irq_data->domain = domain;

        for (parent = domain->parent; parent; parent = parent->parent) {
            irq_data = irq_domain_insert_irq_data(parent, irq_data);
            if (!irq_data) {
                irq_domain_free_irq_data(virq, i + 1);
                return -ENOMEM;
            }
        }
    }

    return 0;
}

int irq_domain_alloc_irqs_hierarchy(struct irq_domain *domain,
                    unsigned int irq_base,
                    unsigned int nr_irqs, void *arg)
{
    if (!domain->ops->alloc) {
        pr_debug("domain->ops->alloc() is NULL\n");
        return -ENOSYS;
    }

    return domain->ops->alloc(domain, irq_base, nr_irqs, arg);
}

static int irq_domain_trim_hierarchy(unsigned int virq)
{
    struct irq_data *tail, *irqd, *irq_data;

    irq_data = irq_get_irq_data(virq);
    tail = NULL;

    /* The first entry must have a valid irqchip */
    if (IS_ERR_OR_NULL(irq_data->chip))
        return -EINVAL;

    /*
     * Validate that the irq_data chain is sane in the presence of
     * a hierarchy trimming marker.
     */
    for (irqd = irq_data->parent_data; irqd; irq_data = irqd, irqd = irqd->parent_data) {
        /* Can't have a valid irqchip after a trim marker */
        if (irqd->chip && tail)
            return -EINVAL;

        /* Can't have an empty irqchip before a trim marker */
        if (!irqd->chip && !tail)
            return -EINVAL;

        if (IS_ERR(irqd->chip)) {
            /* Only -ENOTCONN is a valid trim marker */
            if (PTR_ERR(irqd->chip) != -ENOTCONN)
                return -EINVAL;

            tail = irq_data;
        }
    }

    /* No trim marker, nothing to do */
    if (!tail)
        return 0;

    pr_info("IRQ%d: trimming hierarchy from %s\n",
        virq, tail->parent_data->domain->name);

    /* Sever the inner part of the hierarchy...  */
    irqd = tail;
    tail = tail->parent_data;
    irqd->parent_data = NULL;
    __irq_domain_free_hierarchy(tail);

    return 0;
}

static void irq_domain_insert_irq(int virq)
{
    struct irq_data *data;

    for (data = irq_get_irq_data(virq); data; data = data->parent_data) {
        struct irq_domain *domain = data->domain;

        domain->mapcount++;
        irq_domain_set_mapping(domain, data->hwirq, data);
    }

    irq_clear_status_flags(virq, IRQ_NOREQUEST);
}

static int irq_domain_alloc_irqs_locked(struct irq_domain *domain, int irq_base,
                    unsigned int nr_irqs, int node, void *arg,
                    bool realloc, const struct irq_affinity_desc *affinity)
{
    int i, ret, virq;

    if (realloc && irq_base >= 0) {
        virq = irq_base;
    } else {
        virq = irq_domain_alloc_descs(irq_base, nr_irqs, 0, node,
                          affinity);
        if (virq < 0) {
            pr_debug("cannot allocate IRQ(base %d, count %d)\n",
                 irq_base, nr_irqs);
            return virq;
        }
    }

    if (irq_domain_alloc_irq_data(domain, virq, nr_irqs)) {
        pr_debug("cannot allocate memory for IRQ%d\n", virq);
        ret = -ENOMEM;
        goto out_free_desc;
    }

    ret = irq_domain_alloc_irqs_hierarchy(domain, virq, nr_irqs, arg);
    if (ret < 0)
        goto out_free_irq_data;

    for (i = 0; i < nr_irqs; i++) {
        ret = irq_domain_trim_hierarchy(virq + i);
        if (ret)
            goto out_free_irq_data;
    }

    for (i = 0; i < nr_irqs; i++)
        irq_domain_insert_irq(virq + i);

    return virq;

out_free_irq_data:
    irq_domain_free_irq_data(virq, nr_irqs);
out_free_desc:
    irq_free_descs(virq, nr_irqs);
    return ret;
}

unsigned int irq_create_fwspec_mapping(struct irq_fwspec *fwspec)
{
    struct irq_domain *domain;
    struct irq_data *irq_data;
    irq_hw_number_t hwirq;
    unsigned int type = IRQ_TYPE_NONE;
    int virq;

    if (fwspec->fwnode) {
        domain = irq_find_matching_fwspec(fwspec, DOMAIN_BUS_WIRED);
        if (!domain)
            domain = irq_find_matching_fwspec(fwspec, DOMAIN_BUS_ANY);
    } else {
        domain = irq_default_domain;
    }

    if (!domain) {
        pr_warn("no irq domain found for %s !\n",
            of_node_full_name(to_of_node(fwspec->fwnode)));
        return 0;
    }

    if (irq_domain_translate(domain, fwspec, &hwirq, &type))
        return 0;

    /*
     * WARN if the irqchip returns a type with bits
     * outside the sense mask set and clear these bits.
     */
    if (WARN_ON(type & ~IRQ_TYPE_SENSE_MASK))
        type &= IRQ_TYPE_SENSE_MASK;

    mutex_lock(&domain->root->mutex);

    /*
     * If we've already configured this interrupt,
     * don't do it again, or hell will break loose.
     */
    virq = irq_find_mapping(domain, hwirq);
    if (virq) {
        /*
         * If the trigger type is not specified or matches the
         * current trigger type then we are done so return the
         * interrupt number.
         */
        if (type == IRQ_TYPE_NONE || type == irq_get_trigger_type(virq))
            goto out;

        /*
         * If the trigger type has not been set yet, then set
         * it now and return the interrupt number.
         */
        if (irq_get_trigger_type(virq) == IRQ_TYPE_NONE) {
            irq_data = irq_get_irq_data(virq);
            if (!irq_data) {
                virq = 0;
                goto out;
            }

            irqd_set_trigger_type(irq_data, type);
            goto out;
        }

        pr_warn("type mismatch, failed to map hwirq-%lu for %s!\n",
            hwirq, of_node_full_name(to_of_node(fwspec->fwnode)));
        virq = 0;
        goto out;
    }

    if (irq_domain_is_hierarchy(domain)) {
        if (irq_domain_is_msi_device(domain)) {
            mutex_unlock(&domain->root->mutex);
            virq = msi_device_domain_alloc_wired(domain, hwirq, type);
            mutex_lock(&domain->root->mutex);
        } else
            virq = irq_domain_alloc_irqs_locked(domain, -1, 1, NUMA_NO_NODE,
                                fwspec, false, NULL);
        if (virq <= 0) {
            virq = 0;
            goto out;
        }
    } else {
        /* Create mapping */
        virq = irq_create_mapping_affinity_locked(domain, hwirq, NULL);
        if (!virq)
            goto out;
    }

    printk("%s: virq(%u) -> hwirq(%u)\n", __func__, virq, hwirq);

    irq_data = irq_get_irq_data(virq);
    if (WARN_ON(!irq_data)) {
        virq = 0;
        goto out;
    }

    /* Store trigger type */
    irqd_set_trigger_type(irq_data, type);
out:
    mutex_unlock(&domain->root->mutex);

    return virq;
}

/**
 * irq_domain_translate_onecell() - Generic translate for direct one cell
 * bindings
 * @d:      Interrupt domain involved in the translation
 * @fwspec: The firmware interrupt specifier to translate
 * @out_hwirq:  Pointer to storage for the hardware interrupt number
 * @out_type:   Pointer to storage for the interrupt type
 */
int irq_domain_translate_onecell(struct irq_domain *d,
                 struct irq_fwspec *fwspec,
                 unsigned long *out_hwirq,
                 unsigned int *out_type)
{
    if (WARN_ON(fwspec->param_count < 1))
        return -EINVAL;
    *out_hwirq = fwspec->param[0];
    *out_type = IRQ_TYPE_NONE;
    return 0;
}

static void __irq_domain_deactivate_irq(struct irq_data *irq_data)
{
    if (irq_data && irq_data->domain) {
        struct irq_domain *domain = irq_data->domain;

        if (domain->ops->deactivate)
            domain->ops->deactivate(domain, irq_data);
        if (irq_data->parent_data)
            __irq_domain_deactivate_irq(irq_data->parent_data);
    }
}

static int __irq_domain_activate_irq(struct irq_data *irqd, bool reserve)
{
    int ret = 0;

    if (irqd && irqd->domain) {
        struct irq_domain *domain = irqd->domain;

        if (irqd->parent_data)
            ret = __irq_domain_activate_irq(irqd->parent_data,
                            reserve);
        if (!ret && domain->ops->activate) {
            ret = domain->ops->activate(domain, irqd, reserve);
            /* Rollback in case of error */
            if (ret && irqd->parent_data)
                __irq_domain_deactivate_irq(irqd->parent_data);
        }
    }
    return ret;
}

/**
 * irq_domain_activate_irq - Call domain_ops->activate recursively to activate
 *               interrupt
 * @irq_data:   Outermost irq_data associated with interrupt
 * @reserve:    If set only reserve an interrupt vector instead of assigning one
 *
 * This is the second step to call domain_ops->activate to program interrupt
 * controllers, so the interrupt could actually get delivered.
 */
int irq_domain_activate_irq(struct irq_data *irq_data, bool reserve)
{
    int ret = 0;

    if (!irqd_is_activated(irq_data))
        ret = __irq_domain_activate_irq(irq_data, reserve);
    if (!ret)
        irqd_set_activated(irq_data);
    return ret;
}
