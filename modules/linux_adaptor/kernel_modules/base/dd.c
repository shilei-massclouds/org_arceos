#include <linux/device.h>
#include <linux/async.h>

#include "base.h"
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

static int __device_attach_driver(struct device_driver *drv, void *_data)
{
    PANIC("");
}

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

static int really_probe(struct device *dev, const struct device_driver *drv)
{
    bool test_remove = IS_ENABLED(CONFIG_DEBUG_TEST_DRIVER_REMOVE) &&
               !drv->suppress_bind_attrs;
    int ret, link_ret;

    PANIC("");
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
    PANIC("");
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
    PANIC("");
    return ret;
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

    PANIC("");
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
