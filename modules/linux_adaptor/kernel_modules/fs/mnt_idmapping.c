#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mnt_idmapping.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>

#include "internal.h"

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
