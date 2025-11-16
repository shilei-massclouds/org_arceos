#include <linux/device.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>

#include "adaptor.h"

/* Invalid Xarray index which is outside of any searchable range */
#define MSI_XA_MAX_INDEX    (ULONG_MAX - 1)
/* The maximum domain size */
#define MSI_XA_DOMAIN_SIZE  (MSI_MAX_INDEX + 1)

/**
 * msi_device_domain_alloc_wired - Allocate a "wired" interrupt on @domain
 * @domain: The domain to allocate on
 * @hwirq:  The hardware interrupt number to allocate for
 * @type:   The interrupt type
 *
 * This weirdness supports wire to MSI controllers like MBIGEN.
 *
 * @hwirq is the hardware interrupt number which is handed in from
 * irq_create_fwspec_mapping(). As the wire to MSI domain is sparse, but
 * sized in firmware, the hardware interrupt number cannot be used as MSI
 * index. For the underlying irq chip the MSI index is irrelevant and
 * all it needs is the hardware interrupt number.
 *
 * To handle this the MSI index is allocated with MSI_ANY_INDEX and the
 * hardware interrupt number is stored along with the type information in
 * msi_desc::cookie so the underlying interrupt chip and domain code can
 * retrieve it.
 *
 * Return: The Linux interrupt number (> 0) or an error code
 */
int msi_device_domain_alloc_wired(struct irq_domain *domain, unsigned int hwirq,
                  unsigned int type)
{
    PANIC("");
}

static irq_hw_number_t msi_domain_ops_get_hwirq(struct msi_domain_info *info,
                        msi_alloc_info_t *arg)
{
    return arg->hwirq;
}

static int msi_domain_ops_prepare(struct irq_domain *domain, struct device *dev,
                  int nvec, msi_alloc_info_t *arg)
{
    memset(arg, 0, sizeof(*arg));
    return 0;
}

static void msi_domain_ops_set_desc(msi_alloc_info_t *arg,
                    struct msi_desc *desc)
{
    arg->desc = desc;
}

static int msi_domain_ops_init(struct irq_domain *domain,
                   struct msi_domain_info *info,
                   unsigned int virq, irq_hw_number_t hwirq,
                   msi_alloc_info_t *arg)
{
    irq_domain_set_hwirq_and_chip(domain, virq, hwirq, info->chip,
                      info->chip_data);
    if (info->handler && info->handler_name) {
        __irq_set_handler(virq, info->handler, 0, info->handler_name);
        if (info->handler_data)
            irq_set_handler_data(virq, info->handler_data);
    }
    return 0;
}

static struct msi_domain_ops msi_domain_ops_default = {
    .get_hwirq      = msi_domain_ops_get_hwirq,
    .msi_init       = msi_domain_ops_init,
    .msi_prepare        = msi_domain_ops_prepare,
    .set_desc       = msi_domain_ops_set_desc,
};

static int msi_domain_alloc(struct irq_domain *domain, unsigned int virq,
                unsigned int nr_irqs, void *arg)
{
    PANIC("");
}

static void msi_domain_free(struct irq_domain *domain, unsigned int virq,
                unsigned int nr_irqs)
{
    PANIC("");
}

static int msi_domain_activate(struct irq_domain *domain,
                   struct irq_data *irq_data, bool early)
{
    PANIC("");
}

static void msi_domain_deactivate(struct irq_domain *domain,
                  struct irq_data *irq_data)
{
    PANIC("");
}

static int msi_domain_translate(struct irq_domain *domain, struct irq_fwspec *fwspec,
                irq_hw_number_t *hwirq, unsigned int *type)
{
    PANIC("");
}

static const struct irq_domain_ops msi_domain_ops = {
    .alloc      = msi_domain_alloc,
    .free       = msi_domain_free,
    .activate   = msi_domain_activate,
    .deactivate = msi_domain_deactivate,
    .translate  = msi_domain_translate,
};

static void msi_domain_update_dom_ops(struct msi_domain_info *info)
{
    struct msi_domain_ops *ops = info->ops;

    if (ops == NULL) {
        info->ops = &msi_domain_ops_default;
        return;
    }

    if (!(info->flags & MSI_FLAG_USE_DEF_DOM_OPS))
        return;

    if (ops->get_hwirq == NULL)
        ops->get_hwirq = msi_domain_ops_default.get_hwirq;
    if (ops->msi_init == NULL)
        ops->msi_init = msi_domain_ops_default.msi_init;
    if (ops->msi_prepare == NULL)
        ops->msi_prepare = msi_domain_ops_default.msi_prepare;
    if (ops->set_desc == NULL)
        ops->set_desc = msi_domain_ops_default.set_desc;
}

static void msi_domain_update_chip_ops(struct msi_domain_info *info)
{
    struct irq_chip *chip = info->chip;

    BUG_ON(!chip || !chip->irq_mask || !chip->irq_unmask);
    if (!chip->irq_set_affinity && !(info->flags & MSI_FLAG_NO_AFFINITY))
        chip->irq_set_affinity = msi_domain_set_affinity;
}

static struct irq_domain *__msi_create_irq_domain(struct fwnode_handle *fwnode,
                          struct msi_domain_info *info,
                          unsigned int flags,
                          struct irq_domain *parent)
{
    struct irq_domain *domain;

    if (info->hwsize > MSI_XA_DOMAIN_SIZE)
        return NULL;

    /*
     * Hardware size 0 is valid for backwards compatibility and for
     * domains which are not backed by a hardware table. Grant the
     * maximum index space.
     */
    if (!info->hwsize)
        info->hwsize = MSI_XA_DOMAIN_SIZE;

    msi_domain_update_dom_ops(info);
    if (info->flags & MSI_FLAG_USE_DEF_CHIP_OPS)
        msi_domain_update_chip_ops(info);

    domain = irq_domain_create_hierarchy(parent, flags | IRQ_DOMAIN_FLAG_MSI, 0,
                         fwnode, &msi_domain_ops, info);

    if (domain) {
        irq_domain_update_bus_token(domain, info->bus_token);
        if (info->flags & MSI_FLAG_PARENT_PM_DEV)
            domain->pm_dev = parent->pm_dev;
    }

    return domain;
}

/**
 * msi_create_irq_domain - Create an MSI interrupt domain
 * @fwnode: Optional fwnode of the interrupt controller
 * @info:   MSI domain info
 * @parent: Parent irq domain
 *
 * Return: pointer to the created &struct irq_domain or %NULL on failure
 */
struct irq_domain *msi_create_irq_domain(struct fwnode_handle *fwnode,
                     struct msi_domain_info *info,
                     struct irq_domain *parent)
{
    return __msi_create_irq_domain(fwnode, info, 0, parent);
}

static inline void irq_chip_write_msi_msg(struct irq_data *data,
                      struct msi_msg *msg)
{
    data->chip->irq_write_msi_msg(data, msg);
}

static void msi_check_level(struct irq_domain *domain, struct msi_msg *msg)
{
    struct msi_domain_info *info = domain->host_data;

    /*
     * If the MSI provider has messed with the second message and
     * not advertized that it is level-capable, signal the breakage.
     */
    WARN_ON(!((info->flags & MSI_FLAG_LEVEL_CAPABLE) &&
          (info->chip->flags & IRQCHIP_SUPPORTS_LEVEL_MSI)) &&
        (msg[1].address_lo || msg[1].address_hi || msg[1].data));
}

/**
 * msi_domain_set_affinity - Generic affinity setter function for MSI domains
 * @irq_data:   The irq data associated to the interrupt
 * @mask:   The affinity mask to set
 * @force:  Flag to enforce setting (disable online checks)
 *
 * Intended to be used by MSI interrupt controllers which are
 * implemented with hierarchical domains.
 *
 * Return: IRQ_SET_MASK_* result code
 */
int msi_domain_set_affinity(struct irq_data *irq_data,
                const struct cpumask *mask, bool force)
{
    struct irq_data *parent = irq_data->parent_data;
    struct msi_msg msg[2] = { [1] = { }, };
    int ret;

    ret = parent->chip->irq_set_affinity(parent, mask, force);
    if (ret >= 0 && ret != IRQ_SET_MASK_OK_DONE) {
        BUG_ON(irq_chip_compose_msi_msg(irq_data, msg));
        msi_check_level(irq_data->domain, msg);
        irq_chip_write_msi_msg(irq_data, msg);
    }

    return ret;
}

/**
 * msi_setup_device_data - Setup MSI device data
 * @dev:    Device for which MSI device data should be set up
 *
 * Return: 0 on success, appropriate error code otherwise
 *
 * This can be called more than once for @dev. If the MSI device data is
 * already allocated the call succeeds. The allocated memory is
 * automatically released when the device is destroyed.
 */
int msi_setup_device_data(struct device *dev)
{
    PANIC("");
}
