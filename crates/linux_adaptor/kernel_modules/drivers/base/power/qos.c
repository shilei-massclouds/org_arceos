// SPDX-License-Identifier: GPL-2.0
/*
 * Devices PM QoS constraints management
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 *
 * This module exposes the interface to kernel space for specifying
 * per-device PM QoS dependencies. It provides infrastructure for registration
 * of:
 *
 * Dependents on a QoS value : register requests
 * Watchers of QoS value : get notified when target QoS value changes
 *
 * This QoS design is best effort based. Dependents register their QoS needs.
 * Watchers register to keep track of the current QoS needs of the system.
 * Watchers can register a per-device notification callback using the
 * dev_pm_qos_*_notifier API. The notification chain data is stored in the
 * per-device constraint data struct.
 *
 * Note about the per-device constraint data struct allocation:
 * . The per-device constraints data struct ptr is stored into the device
 *    dev_pm_info.
 * . To minimize the data usage by the per-device constraints, the data struct
 *   is only allocated at the first call to dev_pm_qos_add_request.
 * . The data is later free'd when the device is removed from the system.
 *  . A global mutex protects the constraints users from the data being
 *     allocated and free'd.
 */

#include <linux/pm_qos.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/export.h>
#include <linux/pm_runtime.h>
#include <linux/err.h>
#include <trace/events/power.h>

#include "power.h"

/**
 * dev_pm_qos_expose_latency_tolerance - Expose latency tolerance to userspace
 * @dev: Device whose latency tolerance to expose
 */
int dev_pm_qos_expose_latency_tolerance(struct device *dev)
{
    int ret;

    if (!dev->power.set_latency_tolerance)
        return -EINVAL;

#if 0
    mutex_lock(&dev_pm_qos_sysfs_mtx);
    ret = pm_qos_sysfs_add_latency_tolerance(dev);
    mutex_unlock(&dev_pm_qos_sysfs_mtx);

    return ret;
#endif
    pr_notice("%s: No impl.", __func__);
    return 0;
}
