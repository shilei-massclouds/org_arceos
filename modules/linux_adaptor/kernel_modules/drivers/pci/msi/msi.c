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

/* PCI/MSI-X specific functionality */

static void pci_msix_clear_and_set_ctrl(struct pci_dev *dev, u16 clear, u16 set)
{
    u16 ctrl;

    pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &ctrl);
    ctrl &= ~clear;
    ctrl |= set;
    pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, ctrl);
}

static void __iomem *msix_map_region(struct pci_dev *dev,
                     unsigned int nr_entries)
{
    resource_size_t phys_addr;
    u32 table_offset;
    unsigned long flags;
    u8 bir;

    pci_read_config_dword(dev, dev->msix_cap + PCI_MSIX_TABLE,
                  &table_offset);
    bir = (u8)(table_offset & PCI_MSIX_TABLE_BIR);
    flags = pci_resource_flags(dev, bir);
    if (!flags || (flags & IORESOURCE_UNSET))
        return NULL;

    table_offset &= PCI_MSIX_TABLE_OFFSET;
    phys_addr = pci_resource_start(dev, bir) + table_offset;

    return ioremap(phys_addr, nr_entries * PCI_MSIX_ENTRY_SIZE);
}

static int msix_setup_msi_descs(struct pci_dev *dev, struct msix_entry *entries,
                int nvec, struct irq_affinity_desc *masks)
{
    int ret = 0, i, vec_count = pci_msix_vec_count(dev);
    struct irq_affinity_desc *curmsk;
    struct msi_desc desc;

    memset(&desc, 0, sizeof(desc));

    for (i = 0, curmsk = masks; i < nvec; i++, curmsk++) {
        desc.msi_index = entries ? entries[i].entry : i;
        desc.affinity = masks ? curmsk : NULL;
        desc.pci.msi_attrib.is_virtual = desc.msi_index >= vec_count;

        msix_prepare_msi_desc(dev, &desc);

        ret = msi_insert_msi_desc(&dev->dev, &desc);
        if (ret)
            break;
    }
    return ret;
}

static int msi_verify_entries(struct pci_dev *dev)
{
    struct msi_desc *entry;

    if (!dev->no_64bit_msi)
        return 0;

    msi_for_each_desc(entry, &dev->dev, MSI_DESC_ALL) {
        if (entry->msg.address_hi) {
            pci_err(dev, "arch assigned 64-bit MSI address %#x%08x but device only supports 32 bits\n",
                entry->msg.address_hi, entry->msg.address_lo);
            break;
        }
    }
    return !entry ? 0 : -EIO;
}

static void msix_update_entries(struct pci_dev *dev, struct msix_entry *entries)
{
    struct msi_desc *desc;

    if (entries) {
        msi_for_each_desc(desc, &dev->dev, MSI_DESC_ALL) {
            entries->vector = desc->irq;
            entries++;
        }
    }
}

static int msix_setup_interrupts(struct pci_dev *dev, struct msix_entry *entries,
                 int nvec, struct irq_affinity *affd)
{
    struct irq_affinity_desc *masks = NULL;
    int ret;

    if (affd)
        masks = irq_create_affinity_masks(nvec, affd);

    msi_lock_descs(&dev->dev);
    ret = msix_setup_msi_descs(dev, entries, nvec, masks);
    if (ret)
        goto out_free;

    ret = pci_msi_setup_msi_irqs(dev, nvec, PCI_CAP_ID_MSIX);
    if (ret)
        goto out_free;

    /* Check if all MSI entries honor device restrictions */
    ret = msi_verify_entries(dev);
    if (ret)
        goto out_free;

    msix_update_entries(dev, entries);
    goto out_unlock;

out_free:
    pci_free_msi_irqs(dev);
out_unlock:
    msi_unlock_descs(&dev->dev);
    kfree(masks);
    return ret;
}

static void pci_intx_for_msi(struct pci_dev *dev, int enable)
{
    if (!(dev->dev_flags & PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG))
        pci_intx(dev, enable);
}

static void msix_mask_all(void __iomem *base, int tsize)
{
    u32 ctrl = PCI_MSIX_ENTRY_CTRL_MASKBIT;
    int i;

    for (i = 0; i < tsize; i++, base += PCI_MSIX_ENTRY_SIZE)
        writel(ctrl, base + PCI_MSIX_ENTRY_VECTOR_CTRL);
}

/**
 * msix_capability_init - configure device's MSI-X capability
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * @entries: pointer to an array of struct msix_entry entries
 * @nvec: number of @entries
 * @affd: Optional pointer to enable automatic affinity assignment
 *
 * Setup the MSI-X capability structure of device function with a
 * single MSI-X IRQ. A return of zero indicates the successful setup of
 * requested MSI-X entries with allocated IRQs or non-zero for otherwise.
 **/
static int msix_capability_init(struct pci_dev *dev, struct msix_entry *entries,
                int nvec, struct irq_affinity *affd)
{
    int ret, tsize;
    u16 control;

    /*
     * Some devices require MSI-X to be enabled before the MSI-X
     * registers can be accessed.  Mask all the vectors to prevent
     * interrupts coming in before they're fully set up.
     */
    pci_msix_clear_and_set_ctrl(dev, 0, PCI_MSIX_FLAGS_MASKALL |
                    PCI_MSIX_FLAGS_ENABLE);

    /* Mark it enabled so setup functions can query it */
    dev->msix_enabled = 1;

    pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &control);
    /* Request & Map MSI-X table region */
    tsize = msix_table_size(control);
    dev->msix_base = msix_map_region(dev, tsize);
    if (!dev->msix_base) {
        ret = -ENOMEM;
        goto out_disable;
    }

    ret = msix_setup_interrupts(dev, entries, nvec, affd);
    if (ret)
        goto out_disable;

    /* Disable INTX */
    pci_intx_for_msi(dev, 0);

    if (!pci_msi_domain_supports(dev, MSI_FLAG_NO_MASK, DENY_LEGACY)) {
        /*
         * Ensure that all table entries are masked to prevent
         * stale entries from firing in a crash kernel.
         *
         * Done late to deal with a broken Marvell NVME device
         * which takes the MSI-X mask bits into account even
         * when MSI-X is disabled, which prevents MSI delivery.
         */
        msix_mask_all(dev->msix_base, tsize);
    }
    pci_msix_clear_and_set_ctrl(dev, PCI_MSIX_FLAGS_MASKALL, 0);

    pcibios_free_irq(dev);
    return 0;

out_disable:
    dev->msix_enabled = 0;
    pci_msix_clear_and_set_ctrl(dev, PCI_MSIX_FLAGS_MASKALL | PCI_MSIX_FLAGS_ENABLE, 0);

    return ret;
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

/**
 * msix_prepare_msi_desc - Prepare a half initialized MSI descriptor for operation
 * @dev:    The PCI device for which the descriptor is prepared
 * @desc:   The MSI descriptor for preparation
 *
 * This is separate from msix_setup_msi_descs() below to handle dynamic
 * allocations for MSI-X after initial enablement.
 *
 * Ideally the whole MSI-X setup would work that way, but there is no way to
 * support this for the legacy arch_setup_msi_irqs() mechanism and for the
 * fake irq domains like the x86 XEN one. Sigh...
 *
 * The descriptor is zeroed and only @desc::msi_index and @desc::affinity
 * are set. When called from msix_setup_msi_descs() then the is_virtual
 * attribute is initialized as well.
 *
 * Fill in the rest.
 */
void msix_prepare_msi_desc(struct pci_dev *dev, struct msi_desc *desc)
{
    desc->nvec_used             = 1;
    desc->pci.msi_attrib.is_msix        = 1;
    desc->pci.msi_attrib.is_64      = 1;
    desc->pci.msi_attrib.default_irq    = dev->irq;
    desc->pci.mask_base         = dev->msix_base;


    if (!pci_msi_domain_supports(dev, MSI_FLAG_NO_MASK, DENY_LEGACY) &&
        !desc->pci.msi_attrib.is_virtual) {
        void __iomem *addr = pci_msix_desc_addr(desc);

        desc->pci.msi_attrib.can_mask = 1;
        /* Workaround for SUN NIU insanity, which requires write before read */
        if (dev->dev_flags & PCI_DEV_FLAGS_MSIX_TOUCH_ENTRY_DATA_FIRST)
            writel(0, addr + PCI_MSIX_ENTRY_DATA);
        desc->pci.msix_ctrl = readl(addr + PCI_MSIX_ENTRY_VECTOR_CTRL);
    }
}

/* Common interfaces */

void pci_free_msi_irqs(struct pci_dev *dev)
{
    pci_msi_teardown_msi_irqs(dev);

    if (dev->msix_base) {
        iounmap(dev->msix_base);
        dev->msix_base = NULL;
    }
}
