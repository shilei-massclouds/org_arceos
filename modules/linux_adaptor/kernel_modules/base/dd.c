#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/dma-map-ops.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/async.h>
#include <linux/pm_runtime.h>
#include <linux/pinctrl/devinfo.h>
#include <linux/slab.h>

#include "base.h"
//#include "power/power.h"

#include "../adaptor.h"

static DEFINE_MUTEX(deferred_probe_mutex);
static LIST_HEAD(deferred_probe_pending_list);
static atomic_t deferred_trigger_count = ATOMIC_INIT(0);

static atomic_t probe_count = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(probe_waitqueue);

/*
 * In some cases, like suspend to RAM or hibernation, It might be reasonable
 * to prohibit probing of devices as it could be unsafe.
 * Once defer_all_probes is true all drivers probes will be forcibly deferred.
 */
static bool defer_all_probes;

struct device_attach_data {
    struct device *dev;

    /*
     * Indicates whether we are considering asynchronous probing or
     * not. Only initial binding after device or driver registration
     * (including deferral processing) may be done asynchronously, the
     * rest is always synchronous, as we expect it is being done by
     * request from userspace.
     */
    bool check_async;

    /*
     * Indicates if we are binding synchronous or asynchronous drivers.
     * When asynchronous probing is enabled we'll execute 2 passes
     * over drivers: first pass doing synchronous probing and second
     * doing asynchronous probing (if synchronous did not succeed -
     * most likely because there was no driver requiring synchronous
     * probing - and we found asynchronous driver during first pass).
     * The 2 passes are done because we can't shoot asynchronous
     * probe for given device and driver from bus_for_each_drv() since
     * driver pointer is not guaranteed to stay valid once
     * bus_for_each_drv() iterates to the next driver on the bus.
     */
    bool want_async;

    /*
     * We'll set have_async to 'true' if, while scanning for matching
     * driver, we'll encounter one that requests asynchronous probing.
     */
    bool have_async;
};

static bool driver_deferred_probe_enable;
/**
 * driver_deferred_probe_trigger() - Kick off re-probing deferred devices
 *
 * This functions moves all devices from the pending list to the active
 * list and schedules the deferred probe workqueue to process them.  It
 * should be called anytime a driver is successfully bound to a device.
 *
 * Note, there is a race condition in multi-threaded probe. In the case where
 * more than one device is probing at the same time, it is possible for one
 * probe to complete successfully while another is about to defer. If the second
 * depends on the first, then it will get put on the pending list after the
 * trigger event has already occurred and will be stuck there.
 *
 * The atomic 'deferred_trigger_count' is used to determine if a successful
 * trigger has occurred in the midst of probing a driver. If the trigger count
 * changes in the midst of a probe, then deferred processing should be triggered
 * again.
 */
void driver_deferred_probe_trigger(void)
{
    if (!driver_deferred_probe_enable)
        return;

    PANIC("");
}

static void __device_attach_async_helper(void *_dev, async_cookie_t cookie)
{
    PANIC("");
}

/**
 * device_is_bound() - Check if device is bound to a driver
 * @dev: device to check
 *
 * Returns true if passed device has already finished probing successfully
 * against a driver.
 *
 * This function must be called with the device lock held.
 */
bool device_is_bound(struct device *dev)
{
    return dev->p && klist_node_attached(&dev->p->knode_driver);
}

/**
 * device_bind_driver - bind a driver to one device.
 * @dev: device.
 *
 * Allow manual attachment of a driver to a device.
 * Caller must have already set @dev->driver.
 *
 * Note that this does not modify the bus reference count.
 * Please verify that is accounted for before calling this.
 * (It is ok to call with no other effort from a driver's probe() method.)
 *
 * This function must be called with the device lock held.
 *
 * Callers should prefer to use device_driver_attach() instead.
 */
int device_bind_driver(struct device *dev)
{
    PANIC("");
}

static inline bool cmdline_requested_async_probing(const char *drv_name)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}

static bool driver_allows_async_probing(const struct device_driver *drv)
{
    switch (drv->probe_type) {
    case PROBE_PREFER_ASYNCHRONOUS:
        return true;

    case PROBE_FORCE_SYNCHRONOUS:
        return false;

    default:
        if (cmdline_requested_async_probing(drv->name))
            return true;

        if (module_requested_async_probing(drv->owner))
            return true;

        return false;
    }
}

static int __device_attach_driver(struct device_driver *drv, void *_data);

static int __device_attach(struct device *dev, bool allow_async)
{
    int ret = 0;
    bool async = false;

    device_lock(dev);
    if (dev->p->dead) {
        goto out_unlock;
    } else if (dev->driver) {
        if (device_is_bound(dev)) {
            ret = 1;
            goto out_unlock;
        }
        ret = device_bind_driver(dev);
        if (ret == 0)
            ret = 1;
        else {
            device_set_driver(dev, NULL);
            ret = 0;
        }
    } else {
        struct device_attach_data data = {
            .dev = dev,
            .check_async = allow_async,
            .want_async = false,
        };

#if 0
        if (dev->parent)
            pm_runtime_get_sync(dev->parent);
#endif

        ret = bus_for_each_drv(dev->bus, NULL, &data,
                    __device_attach_driver);
        if (!ret && allow_async && data.have_async) {
            /*
             * If we could not find appropriate driver
             * synchronously and we are allowed to do
             * async probes and there are drivers that
             * want to probe asynchronously, we'll
             * try them.
             */
            dev_dbg(dev, "scheduling asynchronous probe\n");
            get_device(dev);
            async = true;
        } else {
            //pm_request_idle(dev);
        }

#if 0
        if (dev->parent)
            pm_runtime_put(dev->parent);
#endif
    }
out_unlock:
    device_unlock(dev);
    if (async)
        async_schedule_dev(__device_attach_async_helper, dev);
    return ret;
}

void device_initial_probe(struct device *dev)
{
    __device_attach(dev, true);
}

/*
 * __device_driver_lock - acquire locks needed to manipulate dev->drv
 * @dev: Device we will update driver info for
 * @parent: Parent device. Needed if the bus requires parent lock
 *
 * This function will take the required locks for manipulating dev->drv.
 * Normally this will just be the @dev lock, but when called for a USB
 * interface, @parent lock will be held as well.
 */
static void __device_driver_lock(struct device *dev, struct device *parent)
{
    if (parent && dev->bus->need_parent_lock)
        device_lock(parent);
    device_lock(dev);
}

/*
 * __device_driver_unlock - release locks needed to manipulate dev->drv
 * @dev: Device we will update driver info for
 * @parent: Parent device. Needed if the bus requires parent lock
 *
 * This function will release the required locks for manipulating dev->drv.
 * Normally this will just be the @dev lock, but when called for a
 * USB interface, @parent lock will be released as well.
 */
static void __device_driver_unlock(struct device *dev, struct device *parent)
{
    device_unlock(dev);
    if (parent && dev->bus->need_parent_lock)
        device_unlock(parent);
}

static void device_remove(struct device *dev)
{
    //device_remove_file(dev, &dev_attr_state_synced);
    //device_remove_groups(dev, dev->driver->dev_groups);

    if (dev->bus && dev->bus->remove)
        dev->bus->remove(dev);
    else if (dev->driver->remove)
        dev->driver->remove(dev);
}
static void device_unbind_cleanup(struct device *dev)
{
    devres_release_all(dev);
    arch_teardown_dma_ops(dev);
    kfree(dev->dma_range_map);
    dev->dma_range_map = NULL;
    device_set_driver(dev, NULL);
    dev_set_drvdata(dev, NULL);
    if (dev->pm_domain && dev->pm_domain->dismiss)
        dev->pm_domain->dismiss(dev);
    //pm_runtime_reinit(dev);
    dev_pm_set_driver_flags(dev, 0);
}

static int call_driver_probe(struct device *dev, const struct device_driver *drv)
{
    int ret = 0;

    if (dev->bus->probe)
        ret = dev->bus->probe(dev);
    else if (drv->probe)
        ret = drv->probe(dev);

    switch (ret) {
    case 0:
        break;
    case -EPROBE_DEFER:
        /* Driver requested deferred probing */
        dev_dbg(dev, "Driver %s requests probe deferral\n", drv->name);
        break;
    case -ENODEV:
    case -ENXIO:
        dev_dbg(dev, "probe with driver %s rejects match %d\n",
            drv->name, ret);
        break;
    default:
        /* driver matched but the probe failed */
        dev_err(dev, "probe with driver %s failed with error %d\n",
            drv->name, ret);
        break;
    }

    return ret;
}

static void driver_bound(struct device *dev)
{
    if (device_is_bound(dev)) {
        dev_warn(dev, "%s: device already bound\n", __func__);
        return;
    }

    dev_dbg(dev, "driver: '%s': %s: bound to device\n", dev->driver->name,
        __func__);

    klist_add_tail(&dev->p->knode_driver, &dev->driver->p->klist_devices);
    //device_links_driver_bound(dev);

    //device_pm_check_callbacks(dev);

    /*
     * Make sure the device is no longer in one of the deferred lists and
     * kick off retrying all pending devices
     */
    //driver_deferred_probe_del(dev);
    driver_deferred_probe_trigger();

    bus_notify(dev, BUS_NOTIFY_BOUND_DRIVER);
    kobject_uevent(&dev->kobj, KOBJ_BIND);
}

static int really_probe(struct device *dev, const struct device_driver *drv)
{
    bool test_remove = IS_ENABLED(CONFIG_DEBUG_TEST_DRIVER_REMOVE) &&
               !drv->suppress_bind_attrs;
    int ret, link_ret;

    if (defer_all_probes) {
        /*
         * Value of defer_all_probes can be set only by
         * device_block_probing() which, in turn, will call
         * wait_for_device_probe() right after that to avoid any races.
         */
        dev_dbg(dev, "Driver %s force probe deferral\n", drv->name);
        return -EPROBE_DEFER;
    }

#if 0
    link_ret = device_links_check_suppliers(dev);
    if (link_ret == -EPROBE_DEFER)
        return link_ret;
#endif

    dev_dbg(dev, "bus: '%s': %s: probing driver %s with device\n",
        drv->bus->name, __func__, drv->name);
    if (!list_empty(&dev->devres_head)) {
        dev_crit(dev, "Resources present before probing\n");
        ret = -EBUSY;
        goto done;
    }

re_probe:
    device_set_driver(dev, drv);

#if 0
    /* If using pinctrl, bind pins now before probing */
    ret = pinctrl_bind_pins(dev);
    if (ret)
        goto pinctrl_bind_failed;
#endif

    if (dev->bus->dma_configure) {
        ret = dev->bus->dma_configure(dev);
        if (ret)
            goto pinctrl_bind_failed;
    }

#if 0
    ret = driver_sysfs_add(dev);
    if (ret) {
        dev_err(dev, "%s: driver_sysfs_add failed\n", __func__);
        goto sysfs_failed;
    }
#endif

    if (dev->pm_domain && dev->pm_domain->activate) {
        ret = dev->pm_domain->activate(dev);
        if (ret)
            goto probe_failed;
    }

    ret = call_driver_probe(dev, drv);
    if (ret) {
        /*
         * If fw_devlink_best_effort is active (denoted by -EAGAIN), the
         * device might actually probe properly once some of its missing
         * suppliers have probed. So, treat this as if the driver
         * returned -EPROBE_DEFER.
         */
        if (link_ret == -EAGAIN)
            ret = -EPROBE_DEFER;

        /*
         * Return probe errors as positive values so that the callers
         * can distinguish them from other errors.
         */
        ret = -ret;
        goto probe_failed;
    }

#if 0
    ret = device_add_groups(dev, drv->dev_groups);
    if (ret) {
        dev_err(dev, "device_add_groups() failed\n");
        goto dev_groups_failed;
    }

    if (dev_has_sync_state(dev)) {
        ret = device_create_file(dev, &dev_attr_state_synced);
        if (ret) {
            dev_err(dev, "state_synced sysfs add failed\n");
            goto dev_sysfs_state_synced_failed;
        }
    }
#endif

    if (test_remove) {
        test_remove = false;

        device_remove(dev);
        //driver_sysfs_remove(dev);
        if (dev->bus && dev->bus->dma_cleanup)
            dev->bus->dma_cleanup(dev);
        device_unbind_cleanup(dev);

        goto re_probe;
    }

    //pinctrl_init_done(dev);

    if (dev->pm_domain && dev->pm_domain->sync)
        dev->pm_domain->sync(dev);

    driver_bound(dev);
    dev_dbg(dev, "bus: '%s': %s: bound device to driver %s\n",
        drv->bus->name, __func__, drv->name);
    goto done;

dev_sysfs_state_synced_failed:
dev_groups_failed:
    device_remove(dev);
probe_failed:
    //driver_sysfs_remove(dev);
sysfs_failed:
    bus_notify(dev, BUS_NOTIFY_DRIVER_NOT_BOUND);
    if (dev->bus && dev->bus->dma_cleanup)
        dev->bus->dma_cleanup(dev);
pinctrl_bind_failed:
    //device_links_no_driver(dev);
    device_unbind_cleanup(dev);
done:
    return ret;
}

/*
 * For initcall_debug, show the driver probe time.
 */
static int really_probe_debug(struct device *dev, const struct device_driver *drv)
{
    ktime_t calltime, rettime;
    int ret;

    calltime = ktime_get();
    ret = really_probe(dev, drv);
    rettime = ktime_get();
    /*
     * Don't change this to pr_debug() because that requires
     * CONFIG_DYNAMIC_DEBUG and we want a simple 'initcall_debug' on the
     * kernel commandline to print this all the time at the debug level.
     */
    printk(KERN_DEBUG "probe of %s returned %d after %lld usecs\n",
         dev_name(dev), ret, ktime_us_delta(rettime, calltime));
    return ret;
}

static int __driver_probe_device(const struct device_driver *drv, struct device *dev)
{
    int ret = 0;

    if (dev->p->dead || !device_is_registered(dev))
        return -ENODEV;
    if (dev->driver)
        return -EBUSY;

    dev->can_match = true;
    dev_dbg(dev, "bus: '%s': %s: matched device with driver %s\n",
        drv->bus->name, __func__, drv->name);

#if 0
    pm_runtime_get_suppliers(dev);
    if (dev->parent)
        pm_runtime_get_sync(dev->parent);

    pm_runtime_barrier(dev);
#endif
    if (initcall_debug)
        ret = really_probe_debug(dev, drv);
    else
        ret = really_probe(dev, drv);
#if 0
    pm_request_idle(dev);

    if (dev->parent)
        pm_runtime_put(dev->parent);

    pm_runtime_put_suppliers(dev);
#endif
    return ret;
}

/**
 * driver_probe_device - attempt to bind device & driver together
 * @drv: driver to bind a device to
 * @dev: device to try to bind to the driver
 *
 * This function returns -ENODEV if the device is not registered, -EBUSY if it
 * already has a driver, 0 if the device is bound successfully and a positive
 * (inverted) error code for failures from the ->probe method.
 *
 * This function must be called with @dev lock held.  When called for a
 * USB interface, @dev->parent lock must be held as well.
 *
 * If the device has a parent, runtime-resume the parent before driver probing.
 */
static int driver_probe_device(const struct device_driver *drv, struct device *dev)
{
    int trigger_count = atomic_read(&deferred_trigger_count);
    int ret;

    atomic_inc(&probe_count);
    ret = __driver_probe_device(drv, dev);
    if (ret == -EPROBE_DEFER || ret == EPROBE_DEFER) {
        driver_deferred_probe_add(dev);

        /*
         * Did a trigger occur while probing? Need to re-trigger if yes
         */
        if (trigger_count != atomic_read(&deferred_trigger_count) &&
            !defer_all_probes)
            driver_deferred_probe_trigger();
    }
    atomic_dec(&probe_count);
    wake_up_all(&probe_waitqueue);
    return ret;
}

static int __device_attach_driver(struct device_driver *drv, void *_data)
{
    struct device_attach_data *data = _data;
    struct device *dev = data->dev;
    bool async_allowed;
    int ret;

    ret = driver_match_device(drv, dev);
    if (ret == 0) {
        /* no match */
        return 0;
    } else if (ret == -EPROBE_DEFER) {
        dev_dbg(dev, "Device match requests probe deferral\n");
        dev->can_match = true;
        driver_deferred_probe_add(dev);
        /*
         * Device can't match with a driver right now, so don't attempt
         * to match or bind with other drivers on the bus.
         */
        return ret;
    } else if (ret < 0) {
        dev_dbg(dev, "Bus failed to match device: %d\n", ret);
        return ret;
    } /* ret > 0 means positive match */

    async_allowed = driver_allows_async_probing(drv);

    if (async_allowed)
        data->have_async = true;

    if (data->check_async && async_allowed != data->want_async)
        return 0;

    /*
     * Ignore errors returned by ->probe so that the next driver can try
     * its luck.
     */
    ret = driver_probe_device(drv, dev);
    if (ret < 0)
        return ret;
    PANIC("");
    return ret == 0;
}

static int __driver_attach(struct device *dev, void *data)
{
    const struct device_driver *drv = data;
    bool async = false;
    int ret;

    /*
     * Lock device and try to bind to it. We drop the error
     * here and always return 0, because we need to keep trying
     * to bind to devices and some drivers will return an error
     * simply if it didn't support the device.
     *
     * driver_probe_device() will spit a warning if there
     * is an error.
     */

    ret = driver_match_device(drv, dev);
    if (ret == 0) {
        /* no match */
        return 0;
    } else if (ret == -EPROBE_DEFER) {
        dev_dbg(dev, "Device match requests probe deferral\n");
        dev->can_match = true;
        driver_deferred_probe_add(dev);
        /*
         * Driver could not match with device, but may match with
         * another device on the bus.
         */
        return 0;
    } else if (ret < 0) {
        dev_dbg(dev, "Bus failed to match device: %d\n", ret);
        /*
         * Driver could not match with device, but may match with
         * another device on the bus.
         */
        return 0;
    } /* ret > 0 means positive match */

#if 0
    if (driver_allows_async_probing(drv)) {
        /*
         * Instead of probing the device synchronously we will
         * probe it asynchronously to allow for more parallelism.
         *
         * We only take the device lock here in order to guarantee
         * that the dev->driver and async_driver fields are protected
         */
        dev_dbg(dev, "probing driver %s asynchronously\n", drv->name);
        device_lock(dev);
        if (!dev->driver && !dev->p->async_driver) {
            get_device(dev);
            dev->p->async_driver = drv;
            async = true;
        }
        device_unlock(dev);
        if (async)
            async_schedule_dev(__driver_attach_async_helper, dev);
        return 0;
    }
#endif

    __device_driver_lock(dev, dev->parent);
    driver_probe_device(drv, dev);
    __device_driver_unlock(dev, dev->parent);

    return 0;
}

/**
 * driver_attach - try to bind driver to devices.
 * @drv: driver.
 *
 * Walk the list of devices that the bus has on it and try to
 * match the driver with each one.  If driver_probe_device()
 * returns 0 and the @dev->driver is set, we've found a
 * compatible pair.
 */
int driver_attach(const struct device_driver *drv)
{
    /* The (void *) will be put back to const * in __driver_attach() */
    return bus_for_each_dev(drv->bus, NULL, (void *)drv, __driver_attach);
}

void driver_deferred_probe_add(struct device *dev)
{
    if (!dev->can_match)
        return;

    mutex_lock(&deferred_probe_mutex);
    if (list_empty(&dev->p->deferred_probe)) {
        dev_dbg(dev, "Added to deferred list\n");
        list_add_tail(&dev->p->deferred_probe, &deferred_probe_pending_list);
    }
    mutex_unlock(&deferred_probe_mutex);
}
