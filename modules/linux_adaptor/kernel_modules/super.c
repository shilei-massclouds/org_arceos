#include <linux/fs.h>
#include <linux/blk_types.h>

#include "booter.h"

extern void *kmalloc(size_t size, gfp_t flags);

struct dentry *mount_bdev(struct file_system_type *fs_type,
    int flags, const char *dev_name, void *data,
    int (*fill_super)(struct super_block *, void *, int))
{
    if (fill_super == NULL) {
        booter_panic("No ext2 fill_super!");
    }

    struct block_device *bdev;
    bdev = kmalloc(sizeof(struct block_device), 0);

    struct super_block *s;
    s = kmalloc(sizeof(struct super_block), 0);
    s->s_blocksize = 1024;
    s->s_bdev = bdev;
    if (fill_super(s, NULL, 0) != 0) {
        booter_panic("ext2 fill_super error!");
    }

    return s->s_root;
}
