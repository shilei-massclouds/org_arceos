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

time64_t ktime_get_real_seconds(void)
{
    return 0;
}

void mark_buffer_dirty(struct buffer_head *bh)
{
    printk("%s: No impl.\n", __func__);
}

int sync_dirty_buffer(struct buffer_head *bh, int op_flags)
{
    printk("%s: No impl.\n", __func__);
}
