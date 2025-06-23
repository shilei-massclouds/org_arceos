#include <linux/fs.h>
#include "booter.h"

struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
    const struct super_operations *ops = sb->s_op;

    struct inode *inode;
    if (ops->alloc_inode == NULL) {
        booter_panic("no ext2 alloc_inode!");
    }
    inode = ops->alloc_inode(sb);
    inode->i_ino = ino;
    inode->i_state = I_NEW;
    inode->i_sb = sb;

    struct address_space *const mapping = &inode->i_data;
    mapping->host = inode;
    mapping->flags = 0;
    mapping->wb_err = 0;
    atomic_set(&mapping->i_mmap_writable, 0);
    mapping->private_data = NULL;
    mapping->writeback_index = 0;
    inode->i_private = NULL;
    inode->i_mapping = mapping;

    return inode;
}

void clear_nlink(struct inode *inode)
{
    if (inode->i_nlink) {
        inode->__i_nlink = 0;
        atomic_long_inc(&inode->i_sb->s_remove_count);
    }
}

void set_nlink(struct inode *inode, unsigned int nlink)
{
    if (!nlink) {
        clear_nlink(inode);
    } else {
        /* Yes, some filesystems do change nlink from zero to one */
        if (inode->i_nlink == 0)
            atomic_long_dec(&inode->i_sb->s_remove_count);

        inode->__i_nlink = nlink;
    }
}

void unlock_new_inode(struct inode *inode)
{
    inode->i_state &= ~I_NEW & ~I_CREATING;
}
