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

    // inode_init_always
    inode->i_ino = ino;
    inode->i_state = I_NEW;
    inode->i_sb = sb;
    inode->i_blkbits = sb->s_blocksize_bits;

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

void inode_set_flags(struct inode *inode, unsigned int flags,
             unsigned int mask)
{
    WARN_ON_ONCE(flags & ~mask);
    set_mask_bits(&inode->i_flags, mask, flags);
}

/**
 *  bmap    - find a block number in a file
 *  @inode:  inode owning the block number being requested
 *  @block: pointer containing the block to find
 *
 *  Replaces the value in ``*block`` with the block number on the device holding
 *  corresponding to the requested block number in the file.
 *  That is, asked for block 4 of inode 1 the function will replace the
 *  4 in ``*block``, with disk block relative to the disk start that holds that
 *  block of the file.
 *
 *  Returns -EINVAL in case of error, 0 otherwise. If mapping falls into a
 *  hole, returns 0 and ``*block`` is also set to 0.
 */
int bmap(struct inode *inode, sector_t *block)
{
    if (!inode->i_mapping->a_ops->bmap)
        return -EINVAL;

    *block = inode->i_mapping->a_ops->bmap(inode->i_mapping, *block);
    return 0;
}
