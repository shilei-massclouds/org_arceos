#include <linux/device.h>
#include <linux/swiotlb.h>
#include <linux/dma-map-ops.h>

#include "base.h"

/**
 * get_device - increment reference count for device.
 * @dev: device.
 *
 * This simply forwards the call to kobject_get(), though
 * we do take care to provide for the case that we get a NULL
 * pointer passed in.
 */
struct device *get_device(struct device *dev)
{
    return dev ? kobj_to_dev(kobject_get(&dev->kobj)) : NULL;
}

/**
 * put_device - decrement reference count.
 * @dev: device in question.
 */
void put_device(struct device *dev)
{
    /* might_sleep(); */
    if (dev)
        kobject_put(&dev->kobj);
}

/**
 * device_initialize - init device structure.
 * @dev: device.
 *
 * This prepares the device for use by other layers by initializing
 * its fields.
 * It is the first half of device_register(), if called by
 * that function, though it can also be called separately, so one
 * may use @dev's fields. In particular, get_device()/put_device()
 * may be used for reference counting of @dev after calling this
 * function.
 *
 * All fields in @dev must be initialized by the caller to 0, except
 * for those explicitly set to some other value.  The simplest
 * approach is to use kzalloc() to allocate the structure containing
 * @dev.
 *
 * NOTE: Use put_device() to give up your reference instead of freeing
 * @dev directly once you have called this function.
 */
void device_initialize(struct device *dev)
{
    //dev->kobj.kset = devices_kset;
    //kobject_init(&dev->kobj, &device_ktype);
    INIT_LIST_HEAD(&dev->dma_pools);
    mutex_init(&dev->mutex);
    lockdep_set_novalidate_class(&dev->mutex);
    spin_lock_init(&dev->devres_lock);
    INIT_LIST_HEAD(&dev->devres_head);
    //device_pm_init(dev);
    set_dev_node(dev, NUMA_NO_NODE);
    INIT_LIST_HEAD(&dev->links.consumers);
    INIT_LIST_HEAD(&dev->links.suppliers);
    INIT_LIST_HEAD(&dev->links.defer_sync);
    dev->links.status = DL_DEV_NO_DRIVER;
#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
    dev->dma_coherent = dma_default_coherent;
#endif
    swiotlb_dev_init(dev);
}

/**
 * dev_err_probe - probe error check and log helper
 * @dev: the pointer to the struct device
 * @err: error value to test
 * @fmt: printf-style format string
 * @...: arguments as specified in the format string
 *
 * This helper implements common pattern present in probe functions for error
 * checking: print debug or error message depending if the error value is
 * -EPROBE_DEFER and propagate error upwards.
 * In case of -EPROBE_DEFER it sets also defer probe reason, which can be
 * checked later by reading devices_deferred debugfs attribute.
 * It replaces code sequence::
 *
 *  if (err != -EPROBE_DEFER)
 *      dev_err(dev, ...);
 *  else
 *      dev_dbg(dev, ...);
 *  return err;
 *
 * with::
 *
 *  return dev_err_probe(dev, err, ...);
 *
 * Using this helper in your probe function is totally fine even if @err is
 * known to never be -EPROBE_DEFER.
 * The benefit compared to a normal dev_err() is the standardized format
 * of the error code, it being emitted symbolically (i.e. you get "EAGAIN"
 * instead of "-35") and the fact that the error code is returned which allows
 * more compact error paths.
 *
 * Returns @err.
 */
int dev_err_probe(const struct device *dev, int err, const char *fmt, ...)
{
    struct va_format vaf;
    va_list args;

    va_start(args, fmt);
    vaf.fmt = fmt;
    vaf.va = &args;

    switch (err) {
    case -EPROBE_DEFER:
        device_set_deferred_probe_reason(dev, &vaf);
        dev_dbg(dev, "error %pe: %pV", ERR_PTR(err), &vaf);
        break;

    case -ENOMEM:
        /*
         * We don't print anything on -ENOMEM, there is already enough
         * output.
         */
        break;

    default:
        dev_err(dev, "error %pe: %pV", ERR_PTR(err), &vaf);
        break;
    }

    va_end(args);

    return err;
}
