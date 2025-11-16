#include <linux/bitfield.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>

#include "../pci.h"
#include "msi.h"
#include "adaptor.h"

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

    return 1;
}

static bool pci_msix_validate_entries(struct pci_dev *dev, struct msix_entry *entries, int nvec)
{
    bool nogap;
    int i, j;

    if (!entries)
        return true;

    nogap = pci_msi_domain_supports(dev, MSI_FLAG_MSIX_CONTIGUOUS, DENY_LEGACY);

    for (i = 0; i < nvec; i++) {
        /* Check for duplicate entries */
        for (j = i + 1; j < nvec; j++) {
            if (entries[i].entry == entries[j].entry)
                return false;
        }
        /* Check for unsupported gaps */
        if (nogap && entries[i].entry != i)
            return false;
    }
    return true;
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

#if 0
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

static void pcim_msi_release(void *pcidev)
{
    struct pci_dev *dev = pcidev;

    dev->is_msi_managed = false;
    pci_free_irq_vectors(dev);
}

/*
 * Needs to be separate from pcim_release to prevent an ordering problem
 * vs. msi_device_data_release() in the MSI core code.
 */
static int pcim_setup_msi_release(struct pci_dev *dev)
{
    int ret;

    if (!pci_is_managed(dev) || dev->is_msi_managed)
        return 0;

    ret = devm_add_action(&dev->dev, pcim_msi_release, dev);
    if (ret)
        return ret;

    dev->is_msi_managed = true;
    return 0;
}

/*
 * Ordering vs. devres: msi device data has to be installed first so that
 * pcim_msi_release() is invoked before it on device release.
 */
static int pci_setup_msi_context(struct pci_dev *dev)
{
    int ret = msi_setup_device_data(&dev->dev);

    if (ret)
        return ret;

    return pcim_setup_msi_release(dev);
}

/**
 * msi_capability_init - configure device's MSI capability structure
 * @dev: pointer to the pci_dev data structure of MSI device function
 * @nvec: number of interrupts to allocate
 * @affd: description of automatic IRQ affinity assignments (may be %NULL)
 *
 * Setup the MSI capability structure of the device with the requested
 * number of interrupts.  A return value of zero indicates the successful
 * setup of an entry with the new MSI IRQ.  A negative return value indicates
 * an error, and a positive return value indicates the number of interrupts
 * which could have been allocated.
 */
static int msi_capability_init(struct pci_dev *dev, int nvec,
                   struct irq_affinity *affd)
{
    PANIC("");
}

/**
 * pci_msi_vec_count - Return the number of MSI vectors a device can send
 * @dev: device to report about
 *
 * This function returns the number of MSI vectors a device requested via
 * Multiple Message Capable register. It returns a negative errno if the
 * device is not capable sending MSI interrupts. Otherwise, the call succeeds
 * and returns a power of two, up to a maximum of 2^5 (32), according to the
 * MSI specification.
 **/
int pci_msi_vec_count(struct pci_dev *dev)
{
    int ret;
    u16 msgctl;

    if (!dev->msi_cap)
        return -EINVAL;

    pci_read_config_word(dev, dev->msi_cap + PCI_MSI_FLAGS, &msgctl);
    ret = 1 << FIELD_GET(PCI_MSI_FLAGS_QMASK, msgctl);

    return ret;
}

int __pci_enable_msi_range(struct pci_dev *dev, int minvec, int maxvec,
			   struct irq_affinity *affd)
{
	int nvec;
	int rc;

	if (!pci_msi_supported(dev, minvec) || dev->current_state != PCI_D0)
		return -EINVAL;

	/* Check whether driver already requested MSI-X IRQs */
	if (dev->msix_enabled) {
		pci_info(dev, "can't enable MSI (MSI-X already enabled)\n");
		return -EINVAL;
	}

	if (maxvec < minvec)
		return -ERANGE;

	if (WARN_ON_ONCE(dev->msi_enabled))
		return -EINVAL;

	/* Test for the availability of MSI support */
	if (!pci_msi_domain_supports(dev, 0, ALLOW_LEGACY))
		return -ENOTSUPP;

	nvec = pci_msi_vec_count(dev);
	if (nvec < 0)
		return nvec;
	if (nvec < minvec)
		return -ENOSPC;

	if (nvec > maxvec)
		nvec = maxvec;

	rc = pci_setup_msi_context(dev);
	if (rc)
		return rc;

	if (!pci_setup_msi_device_domain(dev))
		return -ENODEV;

	for (;;) {
		if (affd) {
			nvec = irq_calc_affinity_vectors(minvec, nvec, affd);
			if (nvec < minvec)
				return -ENOSPC;
		}

		rc = msi_capability_init(dev, nvec, affd);
		if (rc == 0)
			return nvec;

		if (rc < 0)
			return rc;
		if (rc < minvec)
			return -ENOSPC;

		nvec = rc;
	}
    PANIC("");
}

/* Misc. infrastructure */

struct pci_dev *msi_desc_to_pci_dev(struct msi_desc *desc)
{
    return to_pci_dev(desc->dev);
}

void __pci_write_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
#if 0
    struct pci_dev *dev = msi_desc_to_pci_dev(entry);

    if (dev->current_state != PCI_D0 || pci_dev_is_disconnected(dev)) {
        /* Don't touch the hardware now */
    } else if (entry->pci.msi_attrib.is_msix) {
        pci_write_msg_msix(entry, msg);
    } else {
        pci_write_msg_msi(dev, entry, msg);
    }

    entry->msg = *msg;

    if (entry->write_msi_msg)
        entry->write_msi_msg(entry, entry->write_msi_msg_data);
#endif
    PANIC("");
}
