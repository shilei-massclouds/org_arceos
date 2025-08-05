#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>
#include <linux/export.h>
#include <linux/user_namespace.h>
#include <linux/namei.h>
#include <linux/mnt_idmapping.h>
#include <linux/iversion.h>
#include <linux/security.h>
#include <linux/fsnotify.h>
#include <linux/filelock.h>

#include "internal.h"
#include "../adaptor.h"

static struct posix_acl *__get_acl(struct mnt_idmap *idmap,
                   struct dentry *dentry, struct inode *inode,
                   int type)
{
    pr_err("%s: No impl.", __func__);
    return posix_acl_alloc(1, 0);
}

struct posix_acl *get_inode_acl(struct inode *inode, int type)
{
    return __get_acl(&nop_mnt_idmap, NULL, inode, type);
}

/*
 * Init a fresh posix_acl
 */
void
posix_acl_init(struct posix_acl *acl, int count)
{
    refcount_set(&acl->a_refcount, 1);
    acl->a_count = count;
}

/*
 * Allocate a new ACL with the specified number of entries.
 */
struct posix_acl *
posix_acl_alloc(int count, gfp_t flags)
{
    const size_t size = sizeof(struct posix_acl) +
                        count * sizeof(struct posix_acl_entry);
    struct posix_acl *acl = kmalloc(size, flags);
    if (acl)
        posix_acl_init(acl, count);
    return acl;
}
