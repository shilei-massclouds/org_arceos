#include <linux/kobject.h>

#include "../adaptor.h"

/**
 * kobject_init() - Initialize a kobject structure.
 * @kobj: pointer to the kobject to initialize
 * @ktype: pointer to the ktype for this kobject.
 *
 * This function will properly initialize a kobject such that it can then
 * be passed to the kobject_add() call.
 *
 * After this function is called, the kobject MUST be cleaned up by a call
 * to kobject_put(), not by a call to kfree directly to ensure that all of
 * the memory is cleaned up properly.
 */
void kobject_init(struct kobject *kobj, const struct kobj_type *ktype)
{
    pr_err("%s: No impl.", __func__);
}
