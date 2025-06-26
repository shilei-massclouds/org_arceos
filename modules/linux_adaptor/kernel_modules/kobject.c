#include <linux/kobject.h>
#include <linux/slab.h>

#include "booter.h"

struct kobject *kobject_create_and_add(const char *name, struct kobject *parent)
{
    struct kobject *kobj;
    int retval;

    kobj = kobject_create();
    if (!kobj)
        return NULL;

    return kobj;
}

struct kobject *kobject_create(void)
{
    struct kobject *kobj;

    kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
    if (!kobj)
        return NULL;

    // Note: we may implement kobjec_init in future.
    // kobject_init(kobj, &dynamic_kobj_ktype);
    return kobj;
}

int kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
             struct kobject *parent, const char *fmt, ...)
{
    log_debug("%s: No impl.", __func__);
    return 0;
}
