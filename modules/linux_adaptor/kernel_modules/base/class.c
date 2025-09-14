#include <linux/device/class.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/kdev_t.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include "base.h"

#include "../adaptor.h"

/* /sys/class */
static struct kset *class_kset;

static ssize_t class_attr_show(struct kobject *kobj, struct attribute *attr,
                   char *buf)
{
    PANIC("");
}

static ssize_t class_attr_store(struct kobject *kobj, struct attribute *attr,
                const char *buf, size_t count)
{
    PANIC("");
}

static void class_release(struct kobject *kobj)
{
    struct subsys_private *cp = to_subsys_private(kobj);
    const struct class *class = cp->class;

    pr_debug("class '%s': release.\n", class->name);

    if (class->class_release)
        class->class_release(class);
    else
        pr_debug("class '%s' does not have a release() function, "
             "be careful\n", class->name);

    lockdep_unregister_key(&cp->lock_key);
    kfree(cp);
}

static const struct kobj_ns_type_operations *class_child_ns_type(const struct kobject *kobj)
{
    const struct subsys_private *cp = to_subsys_private(kobj);
    const struct class *class = cp->class;

    return class->ns_type;
}

static const struct sysfs_ops class_sysfs_ops = {
    .show      = class_attr_show,
    .store     = class_attr_store,
};

static const struct kobj_type class_ktype = {
    .sysfs_ops  = &class_sysfs_ops,
    .release    = class_release,
    .child_ns_type  = class_child_ns_type,
};

static struct device *klist_class_to_dev(struct klist_node *n)
{
    struct device_private *p = to_device_private_class(n);
    return p->device;
}

static void klist_class_dev_get(struct klist_node *n)
{
    struct device *dev = klist_class_to_dev(n);

    get_device(dev);
}

static void klist_class_dev_put(struct klist_node *n)
{
    struct device *dev = klist_class_to_dev(n);

    put_device(dev);
}

/**
 * class_to_subsys - Turn a struct class into a struct subsys_private
 *
 * @class: pointer to the struct bus_type to look up
 *
 * The driver core internals need to work on the subsys_private structure, not
 * the external struct class pointer.  This function walks the list of
 * registered classes in the system and finds the matching one and returns the
 * internal struct subsys_private that relates to that class.
 *
 * Note, the reference count of the return value is INCREMENTED if it is not
 * NULL.  A call to subsys_put() must be done when finished with the pointer in
 * order for it to be properly freed.
 */
struct subsys_private *class_to_subsys(const struct class *class)
{
    struct subsys_private *sp = NULL;
    struct kobject *kobj;

    if (!class || !class_kset)
        return NULL;

    spin_lock(&class_kset->list_lock);

    if (list_empty(&class_kset->list))
        goto done;

    list_for_each_entry(kobj, &class_kset->list, entry) {
        struct kset *kset = container_of(kobj, struct kset, kobj);

        sp = container_of_const(kset, struct subsys_private, subsys);
        if (sp->class == class)
            goto done;
    }
    sp = NULL;
done:
    sp = subsys_get(sp);
    spin_unlock(&class_kset->list_lock);
    return sp;
}

/**
 * class_dev_iter_init - initialize class device iterator
 * @iter: class iterator to initialize
 * @class: the class we wanna iterate over
 * @start: the device to start iterating from, if any
 * @type: device_type of the devices to iterate over, NULL for all
 *
 * Initialize class iterator @iter such that it iterates over devices
 * of @class.  If @start is set, the list iteration will start there,
 * otherwise if it is NULL, the iteration starts at the beginning of
 * the list.
 */
void class_dev_iter_init(struct class_dev_iter *iter, const struct class *class,
             const struct device *start, const struct device_type *type)
{
    struct subsys_private *sp = class_to_subsys(class);
    struct klist_node *start_knode = NULL;

    memset(iter, 0, sizeof(*iter));
    if (!sp) {
        pr_crit("%s: class %p was not registered yet\n",
            __func__, class);
        return;
    }

    if (start)
        start_knode = &start->p->knode_class;
    klist_iter_init_node(&sp->klist_devices, &iter->ki, start_knode);
    iter->type = type;
    iter->sp = sp;
}

/**
 * class_dev_iter_next - iterate to the next device
 * @iter: class iterator to proceed
 *
 * Proceed @iter to the next device and return it.  Returns NULL if
 * iteration is complete.
 *
 * The returned device is referenced and won't be released till
 * iterator is proceed to the next device or exited.  The caller is
 * free to do whatever it wants to do with the device including
 * calling back into class code.
 */
struct device *class_dev_iter_next(struct class_dev_iter *iter)
{
    struct klist_node *knode;
    struct device *dev;

    if (!iter->sp)
        return NULL;

    while (1) {
        knode = klist_next(&iter->ki);
        if (!knode)
            return NULL;
        dev = klist_class_to_dev(knode);
        if (!iter->type || iter->type == dev->type)
            return dev;
    }
}

/**
 * class_dev_iter_exit - finish iteration
 * @iter: class iterator to finish
 *
 * Finish an iteration.  Always call this function after iteration is
 * complete whether the iteration ran till the end or not.
 */
void class_dev_iter_exit(struct class_dev_iter *iter)
{
    klist_iter_exit(&iter->ki);
    subsys_put(iter->sp);
}

int class_register(const struct class *cls)
{
    struct subsys_private *cp;
    struct lock_class_key *key;
    int error;

    pr_debug("device class '%s': registering\n", cls->name);

    if (cls->ns_type && !cls->namespace) {
        pr_err("%s: class '%s' does not have namespace\n",
               __func__, cls->name);
        return -EINVAL;
    }
    if (!cls->ns_type && cls->namespace) {
        pr_err("%s: class '%s' does not have ns_type\n",
               __func__, cls->name);
        return -EINVAL;
    }

    cp = kzalloc(sizeof(*cp), GFP_KERNEL);
    if (!cp)
        return -ENOMEM;
    klist_init(&cp->klist_devices, klist_class_dev_get, klist_class_dev_put);
    INIT_LIST_HEAD(&cp->interfaces);
    kset_init(&cp->glue_dirs);
    key = &cp->lock_key;
    lockdep_register_key(key);
    __mutex_init(&cp->mutex, "subsys mutex", key);
    error = kobject_set_name(&cp->subsys.kobj, "%s", cls->name);
    if (error)
        goto err_out;

    cp->subsys.kobj.kset = class_kset;
    cp->subsys.kobj.ktype = &class_ktype;
    cp->class = cls;

    error = kset_register(&cp->subsys);
    if (error)
        goto err_out;

    error = sysfs_create_groups(&cp->subsys.kobj, cls->class_groups);
    if (error) {
        kobject_del(&cp->subsys.kobj);
        kfree_const(cp->subsys.kobj.name);
        goto err_out;
    }
    return 0;

err_out:
    lockdep_unregister_key(key);
    kfree(cp);
    return error;
}

int __init classes_init(void)
{
    class_kset = kset_create_and_add("class", NULL, NULL);
    if (!class_kset)
        return -ENOMEM;
    return 0;
}
