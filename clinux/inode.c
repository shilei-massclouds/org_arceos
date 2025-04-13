#include <linux/fs.h>
#include "booter.h"

void *kmalloc(size_t size, gfp_t flags);

struct dentry *mount_bdev(struct file_system_type *fs_type,
    int flags, const char *dev_name, void *data,
    int (*fill_super)(struct super_block *, void *, int))
{
    if (fill_super == NULL) {
        booter_panic("No ext2 fill_super!");
    }

    struct super_block *s;
    s = kmalloc(sizeof(struct super_block), 0);
    s->s_blocksize = 1024;
    if (fill_super(s, NULL, 0) != 0) {
        booter_panic("ext2 fill_super error!");
    }

    return s->s_root;
}

struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
    const struct super_operations *ops = sb->s_op;

    struct inode *inode;
    if (ops->alloc_inode == NULL) {
        booter_panic("no ext2 alloc_inode!");
    }
    inode = ops->alloc_inode(sb);
    return inode;
}
