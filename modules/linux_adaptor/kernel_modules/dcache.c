#include <linux/fs.h>
#include "booter.h"

void *kmalloc(size_t size, gfp_t flags);

struct dentry *d_make_root(struct inode *root_inode)
{
    struct dentry *dentry = NULL;

    dentry = kmalloc(sizeof(struct dentry), 0);
    if (!dentry)
        return NULL;

    dentry->d_inode = root_inode;

    return dentry;
}
