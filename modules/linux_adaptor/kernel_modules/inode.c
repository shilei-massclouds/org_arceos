#include <linux/fs.h>
#include <linux/prefetch.h>
#include <linux/slab.h>

#include "booter.h"

static void __address_space_init_once(struct address_space *mapping)
{
    xa_init_flags(&mapping->i_pages, XA_FLAGS_LOCK_IRQ | XA_FLAGS_ACCOUNT);
    init_rwsem(&mapping->i_mmap_rwsem);
    INIT_LIST_HEAD(&mapping->private_list);
    spin_lock_init(&mapping->private_lock);
    mapping->i_mmap = RB_ROOT_CACHED;
}

/*
 * These are initializations that only need to be done
 * once, because the fields are idempotent across use
 * of the inode, so let the slab aware of that.
 */
void inode_init_once(struct inode *inode)
{
    memset(inode, 0, sizeof(*inode));
    INIT_HLIST_NODE(&inode->i_hash);
    INIT_LIST_HEAD(&inode->i_devices);
    INIT_LIST_HEAD(&inode->i_io_list);
    INIT_LIST_HEAD(&inode->i_wb_list);
    INIT_LIST_HEAD(&inode->i_lru);
    __address_space_init_once(&inode->i_data);
    i_size_ordered_init(inode);
}

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

void iput(struct inode *inode)
{
    if (!inode)
        return;

    log_error("%s: No impl.", __func__);
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

/**
 *  new_inode   - obtain an inode
 *  @sb: superblock
 *
 *  Allocates a new inode for given superblock. The default gfp_mask
 *  for allocations related to inode->i_mapping is GFP_HIGHUSER_MOVABLE.
 *  If HIGHMEM pages are unsuitable or it is known that pages allocated
 *  for the page cache are not reclaimable or migratable,
 *  mapping_set_gfp_mask() must be called with suitable flags on the
 *  newly created inode's mapping
 *
 */
struct inode *new_inode(struct super_block *sb)
{
    struct inode *inode;

    spin_lock_prefetch(&sb->s_inode_list_lock);

    inode = new_inode_pseudo(sb);
    /*
    if (inode)
        inode_sb_list_add(inode);
        */
    return inode;
}

static struct inode *alloc_inode(struct super_block *sb)
{
    const struct super_operations *ops = sb->s_op;
    struct inode *inode;

    /*
    if (ops->alloc_inode)
        inode = ops->alloc_inode(sb);
    else
        inode = kmem_cache_alloc(inode_cachep, GFP_KERNEL);
        */
    inode = kmalloc(sizeof(struct inode), 0);

    if (!inode)
        return NULL;

    /*
    if (unlikely(inode_init_always(sb, inode))) {
        if (ops->destroy_inode) {
            ops->destroy_inode(inode);
            if (!ops->free_inode)
                return NULL;
        }
        inode->free_inode = ops->free_inode;
        i_callback(&inode->i_rcu);
        return NULL;
    }
    */

    return inode;
}

/**
 *  new_inode_pseudo    - obtain an inode
 *  @sb: superblock
 *
 *  Allocates a new inode for given superblock.
 *  Inode wont be chained in superblock s_inodes list
 *  This means :
 *  - fs can't be unmount
 *  - quotas, fsnotify, writeback can't work
 */
struct inode *new_inode_pseudo(struct super_block *sb)
{
    struct inode *inode = alloc_inode(sb);

    if (inode) {
        spin_lock(&inode->i_lock);
        inode->i_state = 0;
        spin_unlock(&inode->i_lock);
        INIT_LIST_HEAD(&inode->i_sb_list);
    }
    return inode;
}

void touch_atime(const struct path *path)
{
    log_error("%s: No impl.", __func__);
}

/* Caller must hold the file's inode lock */
int file_modified(struct file *file)
{
    log_error("%s: No impl.", __func__);
    return 0;
}

/*
 * Add inode to LRU if needed (inode is unused and clean).
 *
 * Needs inode->i_lock held.
 */
void inode_add_lru(struct inode *inode)
{
#if 0
    if (!(inode->i_state & (I_DIRTY_ALL | I_SYNC |
                I_FREEING | I_WILL_FREE)) &&
        !atomic_read(&inode->i_count) && inode->i_sb->s_flags & SB_ACTIVE)
        inode_lru_list_add(inode);
#endif
    log_error("%s: No impl.", __func__);
}
