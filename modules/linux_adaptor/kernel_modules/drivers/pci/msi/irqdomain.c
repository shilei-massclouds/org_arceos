// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Message Signaled Interrupt (MSI) - irqdomain support
 */
#include <linux/acpi_iort.h>
#include <linux/irqdomain.h>
#include <linux/of_irq.h>

#include "msi.h"
#include "adaptor.h"

/**
 * pci_msi_domain_write_msg - Helper to write MSI message to PCI config space
 * @irq_data:   Pointer to interrupt data of the MSI interrupt
 * @msg:    Pointer to the message
 */
static void pci_msi_domain_write_msg(struct irq_data *irq_data, struct msi_msg *msg)
{
    struct msi_desc *desc = irq_data_get_msi_desc(irq_data);

    /*
     * For MSI-X desc->irq is always equal to irq_data->irq. For
     * MSI only the first interrupt of MULTI MSI passes the test.
     */
    if (desc->irq == irq_data->irq)
        __pci_write_msi_msg(desc, msg);
}

/**
 * pci_msi_domain_calc_hwirq - Generate a unique ID for an MSI source
 * @desc:   Pointer to the MSI descriptor
 *
 * The ID number is only used within the irqdomain.
 */
static irq_hw_number_t pci_msi_domain_calc_hwirq(struct msi_desc *desc)
{
    struct pci_dev *dev = msi_desc_to_pci_dev(desc);

    return (irq_hw_number_t)desc->msi_index |
        pci_dev_id(dev) << 11 |
        ((irq_hw_number_t)(pci_domain_nr(dev->bus) & 0xFFFFFFFF)) << 27;
}

static void pci_msi_domain_set_desc(msi_alloc_info_t *arg,
                    struct msi_desc *desc)
{
    arg->desc = desc;
    arg->hwirq = pci_msi_domain_calc_hwirq(desc);
}

static struct msi_domain_ops pci_msi_domain_ops_default = {
    .set_desc   = pci_msi_domain_set_desc,
};

static void pci_msi_domain_update_dom_ops(struct msi_domain_info *info)
{
    struct msi_domain_ops *ops = info->ops;

    if (ops == NULL) {
        info->ops = &pci_msi_domain_ops_default;
    } else {
        if (ops->set_desc == NULL)
            ops->set_desc = pci_msi_domain_set_desc;
    }
}

static void pci_msi_domain_update_chip_ops(struct msi_domain_info *info)
{
    struct irq_chip *chip = info->chip;

    BUG_ON(!chip);
    if (!chip->irq_write_msi_msg)
        chip->irq_write_msi_msg = pci_msi_domain_write_msg;
    if (!chip->irq_mask)
        chip->irq_mask = pci_msi_mask_irq;
    if (!chip->irq_unmask)
        chip->irq_unmask = pci_msi_unmask_irq;
}

struct irq_domain *pci_msi_create_irq_domain(struct fwnode_handle *fwnode,
                         struct msi_domain_info *info,
                         struct irq_domain *parent)
{
    if (WARN_ON(info->flags & MSI_FLAG_LEVEL_CAPABLE))
        info->flags &= ~MSI_FLAG_LEVEL_CAPABLE;

    if (info->flags & MSI_FLAG_USE_DEF_DOM_OPS)
        pci_msi_domain_update_dom_ops(info);
    if (info->flags & MSI_FLAG_USE_DEF_CHIP_OPS)
        pci_msi_domain_update_chip_ops(info);

    /* Let the core code free MSI descriptors when freeing interrupts */
    info->flags |= MSI_FLAG_FREE_MSI_DESCS;

    info->flags |= MSI_FLAG_ACTIVATE_EARLY | MSI_FLAG_DEV_SYSFS;
    if (IS_ENABLED(CONFIG_GENERIC_IRQ_RESERVATION_MODE))
        info->flags |= MSI_FLAG_MUST_REACTIVATE;

    /* PCI-MSI is oneshot-safe */
    info->chip->flags |= IRQCHIP_ONESHOT_SAFE;
    /* Let the core update the bus token */
    info->bus_token = DOMAIN_BUS_PCI_MSI;

    return msi_create_irq_domain(fwnode, info, parent);
}

/**
 * pci_setup_msi_device_domain - Setup a device MSI interrupt domain
 * @pdev:   The PCI device to create the domain on
 *
 * Return:
 *  True when:
 *  - The device does not have a MSI parent irq domain associated,
 *    which keeps the legacy architecture specific and the global
 *    PCI/MSI domain models working
 *  - The MSI domain exists already
 *  - The MSI domain was successfully allocated
 *  False when:
 *  - MSI-X is enabled
 *  - The domain creation fails.
 *
 * The created MSI domain is preserved until:
 *  - The device is removed
 *  - MSI is disabled and a MSI-X domain is created
 */
bool pci_setup_msi_device_domain(struct pci_dev *pdev)
{
#if 0
    if (WARN_ON_ONCE(pdev->msix_enabled))
        return false;

    if (pci_match_device_domain(pdev, DOMAIN_BUS_PCI_DEVICE_MSI))
        return true;
    if (pci_match_device_domain(pdev, DOMAIN_BUS_PCI_DEVICE_MSIX))
        msi_remove_device_irq_domain(&pdev->dev, MSI_DEFAULT_DOMAIN);

    return pci_create_device_domain(pdev, &pci_msi_template, 1);
#endif
    PANIC("");
}
