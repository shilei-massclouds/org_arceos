#include <linux/device.h>
#include <linux/async.h>

#include "base.h"
#include "../adaptor.h"

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
