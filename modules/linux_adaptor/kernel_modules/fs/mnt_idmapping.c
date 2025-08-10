#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mnt_idmapping.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>

#include "internal.h"
#include "../adaptor.h"

struct mnt_idmap {
    struct uid_gid_map uid_map;
    struct uid_gid_map gid_map;
    refcount_t count;
};

/*
 * Carries the initial idmapping of 0:0:4294967295 which is an identity
 * mapping. This means that {g,u}id 0 is mapped to {g,u}id 0, {g,u}id 1 is
 * mapped to {g,u}id 1, [...], {g,u}id 1000 to {g,u}id 1000, [...].
 */
struct mnt_idmap nop_mnt_idmap = {
    .count  = REFCOUNT_INIT(1),
};

vfsuid_t make_vfsuid(struct mnt_idmap *idmap,
                     struct user_namespace *fs_userns,
                     kuid_t kuid)
{
    uid_t uid;

    if (idmap == &nop_mnt_idmap)
        return VFSUIDT_INIT(kuid);

    PANIC("");
}

vfsgid_t make_vfsgid(struct mnt_idmap *idmap,
             struct user_namespace *fs_userns, kgid_t kgid)
{
    gid_t gid;

    if (idmap == &nop_mnt_idmap)
        return VFSGIDT_INIT(kgid);

    PANIC("");
}

/**
 * vfsgid_in_group_p() - check whether a vfsuid matches the caller's groups
 * @vfsgid: the mnt gid to match
 *
 * This function can be used to determine whether @vfsuid matches any of the
 * caller's groups.
 *
 * Return: 1 if vfsuid matches caller's groups, 0 if not.
 */
int vfsgid_in_group_p(vfsgid_t vfsgid)
{
    pr_err("%s: No impl.", __func__);
    return 1;
}
