// SPDX-License-Identifier: GPL-2.0
/*
 * PCI support in ACPI
 *
 * Copyright (C) 2005 David Shaohua Li <shaohua.li@intel.com>
 * Copyright (C) 2004 Tom Long Nguyen <tom.l.nguyen@intel.com>
 * Copyright (C) 2004 Intel Corp.
 */

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/irqdomain.h>
#include <linux/pci.h>
#include <linux/msi.h>
#include <linux/pci_hotplug.h>
#include <linux/module.h>
#include <linux/pci-acpi.h>
#include <linux/pci-ecam.h>
#include <linux/pm_runtime.h>
#include <linux/pm_qos.h>
#include <linux/rwsem.h>
#include "pci.h"

#include "adaptor.h"

bool acpi_pci_bridge_d3(struct pci_dev *dev)
{
    struct pci_dev *rpdev;
    struct acpi_device *adev, *rpadev;
    const union acpi_object *obj;

    if (acpi_pci_disabled || !dev->is_hotplug_bridge)
        return false;

    adev = ACPI_COMPANION(&dev->dev);
    if (adev) {
        /*
         * If the bridge has _S0W, whether or not it can go into D3
         * depends on what is returned by that object.  In particular,
         * if the power state returned by _S0W is D2 or shallower,
         * entering D3 should not be allowed.
         */
        if (acpi_dev_power_state_for_wake(adev) <= ACPI_STATE_D2)
            return false;

        /*
         * Otherwise, assume that the bridge can enter D3 so long as it
         * is power-manageable via ACPI.
         */
        if (acpi_device_power_manageable(adev))
            return true;
    }

    rpdev = pcie_find_root_port(dev);
    if (!rpdev)
        return false;

    if (rpdev == dev)
        rpadev = adev;
    else
        rpadev = ACPI_COMPANION(&rpdev->dev);

    if (!rpadev)
        return false;

    /*
     * If the Root Port cannot signal wakeup signals at all, i.e., it
     * doesn't supply a wakeup GPE via _PRW, it cannot signal hotplug
     * events from low-power states including D3hot and D3cold.
     */
    if (!rpadev->wakeup.flags.valid)
        return false;

    /*
     * In the bridge-below-a-Root-Port case, evaluate _S0W for the Root Port
     * to verify whether or not it can signal wakeup from D3.
     */
    if (rpadev != adev &&
        acpi_dev_power_state_for_wake(rpadev) <= ACPI_STATE_D2)
        return false;

    /*
     * The "HotPlugSupportInD3" property in a Root Port _DSD indicates
     * the Port can signal hotplug events while in D3.  We assume any
     * bridges *below* that Root Port can also signal hotplug events
     * while in D3.
     */
    if (!acpi_dev_get_property(rpadev, "HotPlugSupportInD3",
                   ACPI_TYPE_INTEGER, &obj) &&
        obj->integer.value == 1)
        return true;

    return false;
}

static void acpi_pci_config_space_access(struct pci_dev *dev, bool enable)
{
    int val = enable ? ACPI_REG_CONNECT : ACPI_REG_DISCONNECT;
    int ret = acpi_evaluate_reg(ACPI_HANDLE(&dev->dev),
                    ACPI_ADR_SPACE_PCI_CONFIG, val);
    if (ret)
        pci_dbg(dev, "ACPI _REG %s evaluation failed (%d)\n",
            enable ? "connect" : "disconnect", ret);
}

int acpi_pci_set_power_state(struct pci_dev *dev, pci_power_t state)
{
    struct acpi_device *adev = ACPI_COMPANION(&dev->dev);
    static const u8 state_conv[] = {
        [PCI_D0] = ACPI_STATE_D0,
        [PCI_D1] = ACPI_STATE_D1,
        [PCI_D2] = ACPI_STATE_D2,
        [PCI_D3hot] = ACPI_STATE_D3_HOT,
        [PCI_D3cold] = ACPI_STATE_D3_COLD,
    };
    int error;

    /* If the ACPI device has _EJ0, ignore the device */
    if (!adev || acpi_has_method(adev->handle, "_EJ0"))
        return -ENODEV;

    switch (state) {
    case PCI_D0:
    case PCI_D1:
    case PCI_D2:
    case PCI_D3hot:
    case PCI_D3cold:
        break;
    default:
        return -EINVAL;
    }

    if (state == PCI_D3cold) {
        if (dev_pm_qos_flags(&dev->dev, PM_QOS_FLAG_NO_POWER_OFF) ==
                PM_QOS_FLAGS_ALL)
            return -EBUSY;

        /* Notify AML lack of PCI config space availability */
        acpi_pci_config_space_access(dev, false);
    }

    error = acpi_device_set_power(adev, state_conv[state]);
    if (error)
        return error;

    pci_dbg(dev, "power state changed by ACPI to %s\n",
            acpi_power_state_string(adev->power.state));

    /*
     * Notify AML of PCI config space availability.  Config space is
     * accessible in all states except D3cold; the only transitions
     * that change availability are transitions to D3cold and from
     * D3cold to D0.
     */
    if (state == PCI_D0)
        acpi_pci_config_space_access(dev, true);

    return 0;
}
