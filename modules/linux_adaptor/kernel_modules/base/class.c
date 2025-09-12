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
