#include <linux/bitfield.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>

#include "../pci/pci.h"
#include "msi.h"
#include "../adaptor.h"

int pci_msi_enable = 1;

/**
 * pci_msi_supported - check whether MSI may be enabled on a device
 * @dev: pointer to the pci_dev data structure of MSI device function
 * @nvec: how many MSIs have been requested?
 *
 * Look at global flags, the device itself, and its parent buses
 * to determine if MSI/-X are supported for the device. If MSI/-X is
 * supported return 1, else return 0.
 **/
static int pci_msi_supported(struct pci_dev *dev, int nvec)
{
    struct pci_bus *bus;

    /* MSI must be globally enabled and supported by the device */
    if (!pci_msi_enable)
        return 0;

    if (!dev || dev->no_msi)
        return 0;

    /*
     * You can't ask to have 0 or less MSIs configured.
     *  a) it's stupid ..
     *  b) the list manipulation code assumes nvec >= 1.
     */
    if (nvec < 1)
        return 0;

    /*
     * Any bridge which does NOT route MSI transactions from its
     * secondary bus to its primary bus must set NO_MSI flag on
     * the secondary pci_bus.
     *
     * The NO_MSI flag can either be set directly by:
     * - arch-specific PCI host bus controller drivers (deprecated)
     * - quirks for specific PCI bridges
     *
     * or indirectly by platform-specific PCI host bridge drivers by
     * advertising the 'msi_domain' property, which results in
     * the NO_MSI flag when no MSI domain is found for this bridge
     * at probe time.
     */
    for (bus = dev->bus; bus; bus = bus->parent)
        if (bus->bus_flags & PCI_BUS_FLAGS_NO_MSI)
            return 0;

    PANIC("");
    return 1;
}

int __pci_enable_msix_range(struct pci_dev *dev, struct msix_entry *entries, int minvec,
                int maxvec, struct irq_affinity *affd, int flags)
{
    int hwsize, rc, nvec = maxvec;

    if (maxvec < minvec)
        return -ERANGE;

    if (dev->msi_enabled) {
        pci_info(dev, "can't enable MSI-X (MSI already enabled)\n");
        return -EINVAL;
    }

    if (WARN_ON_ONCE(dev->msix_enabled))
        return -EINVAL;

    /* Check MSI-X early on irq domain enabled architectures */
    if (!pci_msi_domain_supports(dev, MSI_FLAG_PCI_MSIX, ALLOW_LEGACY))
        return -ENOTSUPP;

#if 0
    if (!pci_msi_supported(dev, nvec) || dev->current_state != PCI_D0)
        return -EINVAL;

    hwsize = pci_msix_vec_count(dev);
    if (hwsize < 0)
        return hwsize;

    if (!pci_msix_validate_entries(dev, entries, nvec))
        return -EINVAL;

    if (hwsize < nvec) {
        /* Keep the IRQ virtual hackery working */
        if (flags & PCI_IRQ_VIRTUAL)
            hwsize = nvec;
        else
            nvec = hwsize;
    }

    if (nvec < minvec)
        return -ENOSPC;

    rc = pci_setup_msi_context(dev);
    if (rc)
        return rc;

    if (!pci_setup_msix_device_domain(dev, hwsize))
        return -ENODEV;

    for (;;) {
        if (affd) {
            nvec = irq_calc_affinity_vectors(minvec, nvec, affd);
            if (nvec < minvec)
                return -ENOSPC;
        }

        rc = msix_capability_init(dev, entries, nvec, affd);
        if (rc == 0)
            return nvec;

        if (rc < 0)
            return rc;
        if (rc < minvec)
            return -ENOSPC;

        nvec = rc;
    }
#endif
    PANIC("");
}

int __pci_enable_msi_range(struct pci_dev *dev, int minvec, int maxvec,
               struct irq_affinity *affd)
{
    int nvec;
    int rc;

    if (!pci_msi_supported(dev, minvec) || dev->current_state != PCI_D0)
        return -EINVAL;

    PANIC("");
}
