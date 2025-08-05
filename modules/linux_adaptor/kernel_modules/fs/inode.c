#include <linux/export.h>
#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/hash.h>
#include <linux/swap.h>
#include <linux/security.h>
#include <linux/cdev.h>
#include <linux/memblock.h>
#include <linux/fsnotify.h>
#include <linux/mount.h>
#include <linux/posix_acl.h>
#include <linux/buffer_head.h> /* for inode_has_buffers */
#include <linux/ratelimit.h>
#include <linux/list_lru.h>
#include <linux/iversion.h>
#include <linux/rw_hint.h>
#include <trace/events/writeback.h>
#include "internal.h"

#include "../adaptor.h"

static DEFINE_PER_CPU(unsigned long, nr_inodes);
static DEFINE_PER_CPU(unsigned long, nr_unused);

static struct kmem_cache *inode_cachep __ro_after_init;

static unsigned int i_hash_mask __ro_after_init;
static unsigned int i_hash_shift __ro_after_init;
static struct hlist_head *inode_hashtable __ro_after_init;
static __cacheline_aligned_in_smp DEFINE_SPINLOCK(inode_hash_lock);

static __initdata unsigned long ihash_entries;

static unsigned long hash(struct super_block *sb, unsigned long hashval)
{
    unsigned long tmp;

    tmp = (hashval * (unsigned long)sb) ^ (GOLDEN_RATIO_PRIME + hashval) /
            L1_CACHE_BYTES;
    tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> i_hash_shift);
    return tmp & i_hash_mask;
}

/*
 * Empty aops. Can be used for the cases where the user does not
 * define any of the address_space operations.
 */
const struct address_space_operations empty_aops = {
};

static void init_once(void *foo)
{
    struct inode *inode = (struct inode *) foo;

    inode_init_once(inode);
}

void free_inode_nonrcu(struct inode *inode)
{
    kmem_cache_free(inode_cachep, inode);
}

static void i_callback(struct rcu_head *head)
{
    struct inode *inode = container_of(head, struct inode, i_rcu);
    if (inode->free_inode)
        inode->free_inode(inode);
    else
        free_inode_nonrcu(inode);
}

static struct inode *alloc_inode(struct super_block *sb)
{
    const struct super_operations *ops = sb->s_op;
    struct inode *inode;

    if (ops->alloc_inode)
        inode = ops->alloc_inode(sb);
    else
        inode = alloc_inode_sb(sb, inode_cachep, GFP_KERNEL);

    if (!inode)
        return NULL;

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
    return alloc_inode(sb);
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

    inode = new_inode_pseudo(sb);
    if (inode)
        inode_sb_list_add(inode);
    return inode;
}

/**
 * inode_sb_list_add - add inode to the superblock list of inodes
 * @inode: inode to add
 */
void inode_sb_list_add(struct inode *inode)
{
    spin_lock(&inode->i_sb->s_inode_list_lock);
    list_add(&inode->i_sb_list, &inode->i_sb->s_inodes);
    spin_unlock(&inode->i_sb->s_inode_list_lock);
}

static void __address_space_init_once(struct address_space *mapping)
{
    xa_init_flags(&mapping->i_pages, XA_FLAGS_LOCK_IRQ | XA_FLAGS_ACCOUNT);
    init_rwsem(&mapping->i_mmap_rwsem);
    INIT_LIST_HEAD(&mapping->i_private_list);
    spin_lock_init(&mapping->i_private_lock);
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
    INIT_LIST_HEAD(&inode->i_sb_list);
    __address_space_init_once(&inode->i_data);
    i_size_ordered_init(inode);
}

static int no_open(struct inode *inode, struct file *file)
{
    return -ENXIO;
}

/**
 * inode_init_always_gfp - perform inode structure initialisation
 * @sb: superblock inode belongs to
 * @inode: inode to initialise
 * @gfp: allocation flags
 *
 * These are initializations that need to be done on every inode
 * allocation as the fields are not initialised by slab allocation.
 * If there are additional allocations required @gfp is used.
 */
int inode_init_always_gfp(struct super_block *sb, struct inode *inode, gfp_t gfp)
{
    static const struct inode_operations empty_iops;
    static const struct file_operations no_open_fops = {.open = no_open};
    struct address_space *const mapping = &inode->i_data;

    inode->i_sb = sb;
    inode->i_blkbits = sb->s_blocksize_bits;
    inode->i_flags = 0;
    inode->i_state = 0;
    atomic64_set(&inode->i_sequence, 0);
    atomic_set(&inode->i_count, 1);
    inode->i_op = &empty_iops;
    inode->i_fop = &no_open_fops;
    inode->i_ino = 0;
    inode->__i_nlink = 1;
    inode->i_opflags = 0;
    if (sb->s_xattr)
        inode->i_opflags |= IOP_XATTR;
    i_uid_write(inode, 0);
    i_gid_write(inode, 0);
    atomic_set(&inode->i_writecount, 0);
    inode->i_size = 0;
    inode->i_write_hint = WRITE_LIFE_NOT_SET;
    inode->i_blocks = 0;
    inode->i_bytes = 0;
    inode->i_generation = 0;
    inode->i_pipe = NULL;
    inode->i_cdev = NULL;
    inode->i_link = NULL;
    inode->i_dir_seq = 0;
    inode->i_rdev = 0;
    inode->dirtied_when = 0;

#ifdef CONFIG_CGROUP_WRITEBACK
    inode->i_wb_frn_winner = 0;
    inode->i_wb_frn_avg_time = 0;
    inode->i_wb_frn_history = 0;
#endif

    spin_lock_init(&inode->i_lock);
    lockdep_set_class(&inode->i_lock, &sb->s_type->i_lock_key);

    init_rwsem(&inode->i_rwsem);
    lockdep_set_class(&inode->i_rwsem, &sb->s_type->i_mutex_key);

    atomic_set(&inode->i_dio_count, 0);

    mapping->a_ops = &empty_aops;
    mapping->host = inode;
    mapping->flags = 0;
    mapping->wb_err = 0;
    atomic_set(&mapping->i_mmap_writable, 0);
#ifdef CONFIG_READ_ONLY_THP_FOR_FS
    atomic_set(&mapping->nr_thps, 0);
#endif
    mapping_set_gfp_mask(mapping, GFP_HIGHUSER_MOVABLE);
    mapping->i_private_data = NULL;
    mapping->writeback_index = 0;
    init_rwsem(&mapping->invalidate_lock);
    lockdep_set_class_and_name(&mapping->invalidate_lock,
                   &sb->s_type->invalidate_lock_key,
                   "mapping.invalidate_lock");
    if (sb->s_iflags & SB_I_STABLE_WRITES)
        mapping_set_stable_writes(mapping);
    inode->i_private = NULL;
    inode->i_mapping = mapping;
    INIT_HLIST_HEAD(&inode->i_dentry);  /* buggered by rcu freeing */
#ifdef CONFIG_FS_POSIX_ACL
    inode->i_acl = inode->i_default_acl = ACL_NOT_CACHED;
#endif

#ifdef CONFIG_FSNOTIFY
    inode->i_fsnotify_mask = 0;
#endif
    inode->i_flctx = NULL;

    /*
    if (unlikely(security_inode_alloc(inode, gfp)))
        return -ENOMEM;
    */

    this_cpu_inc(nr_inodes);

    return 0;
}

/**
 *  __insert_inode_hash - hash an inode
 *  @inode: unhashed inode
 *  @hashval: unsigned long value used to locate this object in the
 *      inode_hashtable.
 *
 *  Add an inode to the inode hash for this superblock.
 */
void __insert_inode_hash(struct inode *inode, unsigned long hashval)
{
    printk("%s: step1\n", __func__);
    struct hlist_head *b = inode_hashtable + hash(inode->i_sb, hashval);

    spin_lock(&inode_hash_lock);
    spin_lock(&inode->i_lock);
    hlist_add_head_rcu(&inode->i_hash, b);
    spin_unlock(&inode->i_lock);
    spin_unlock(&inode_hash_lock);
    printk("%s: step2\n", __func__);
}

/*
 * If we try to find an inode in the inode hash while it is being
 * deleted, we have to wait until the filesystem completes its
 * deletion before reporting that it isn't found.  This function waits
 * until the deletion _might_ have completed.  Callers are responsible
 * to recheck inode state.
 *
 * It doesn't matter if I_NEW is not set initially, a call to
 * wake_up_bit(&inode->i_state, __I_NEW) after removing from the hash list
 * will DTRT.
 */
static void __wait_on_freeing_inode(struct inode *inode, bool is_inode_hash_locked)
{
    PANIC("");
}

/*
 * find_inode_fast is the fast path version of find_inode, see the comment at
 * iget_locked for details.
 */
static struct inode *find_inode_fast(struct super_block *sb,
                struct hlist_head *head, unsigned long ino,
                bool is_inode_hash_locked)
{
    struct inode *inode = NULL;

    if (is_inode_hash_locked)
        lockdep_assert_held(&inode_hash_lock);
    else
        lockdep_assert_not_held(&inode_hash_lock);

    rcu_read_lock();
repeat:
    hlist_for_each_entry_rcu(inode, head, i_hash) {
        if (inode->i_ino != ino)
            continue;
        if (inode->i_sb != sb)
            continue;
        spin_lock(&inode->i_lock);
        if (inode->i_state & (I_FREEING|I_WILL_FREE)) {
            __wait_on_freeing_inode(inode, is_inode_hash_locked);
            goto repeat;
        }
        if (unlikely(inode->i_state & I_CREATING)) {
            spin_unlock(&inode->i_lock);
            rcu_read_unlock();
            return ERR_PTR(-ESTALE);
        }
        __iget(inode);
        spin_unlock(&inode->i_lock);
        rcu_read_unlock();
        return inode;
    }
    rcu_read_unlock();
    return NULL;
}

/*
 * Called when we're dropping the last reference
 * to an inode.
 *
 * Call the FS "drop_inode()" function, defaulting to
 * the legacy UNIX filesystem behaviour.  If it tells
 * us to evict inode, do so.  Otherwise, retain inode
 * in cache if fs is alive, sync and evict if fs is
 * shutting down.
 */
static void iput_final(struct inode *inode)
{
    struct super_block *sb = inode->i_sb;
    const struct super_operations *op = inode->i_sb->s_op;
    unsigned long state;
    int drop;

    WARN_ON(inode->i_state & I_NEW);

    PANIC("");
}

/**
 *  iput    - put an inode
 *  @inode: inode to put
 *
 *  Puts an inode, dropping its usage count. If the inode use count hits
 *  zero, the inode is then freed and may also be destroyed.
 *
 *  Consequently, iput() can sleep.
 */
void iput(struct inode *inode)
{
    if (!inode)
        return;
    BUG_ON(inode->i_state & I_CLEAR);
retry:
    if (atomic_dec_and_lock(&inode->i_count, &inode->i_lock)) {
        if (inode->i_nlink && (inode->i_state & I_DIRTY_TIME)) {
            atomic_inc(&inode->i_count);
            spin_unlock(&inode->i_lock);
            trace_writeback_lazytime_iput(inode);
            mark_inode_dirty_sync(inode);
            goto retry;
        }
        iput_final(inode);
    }
}

/**
 * ilookup - search for an inode in the inode cache
 * @sb:     super block of file system to search
 * @ino:    inode number to search for
 *
 * Search for the inode @ino in the inode cache, and if the inode is in the
 * cache, the inode is returned with an incremented reference count.
 */
struct inode *ilookup(struct super_block *sb, unsigned long ino)
{
    struct hlist_head *head = inode_hashtable + hash(sb, ino);
    struct inode *inode;
again:
    inode = find_inode_fast(sb, head, ino, false);

    if (inode) {
        if (IS_ERR(inode))
            return NULL;
        wait_on_inode(inode);
        if (unlikely(inode_unhashed(inode))) {
            iput(inode);
            goto again;
        }
    }
    return inode;
}

/*
 * get additional reference to inode; caller must already hold one.
 */
void ihold(struct inode *inode)
{
    WARN_ON(atomic_inc_return(&inode->i_count) < 2);
}

static void __inode_add_lru(struct inode *inode, bool rotate)
{
    if (inode->i_state & (I_DIRTY_ALL | I_SYNC | I_FREEING | I_WILL_FREE))
        return;
    if (atomic_read(&inode->i_count))
        return;
    if (!(inode->i_sb->s_flags & SB_ACTIVE))
        return;
    if (!mapping_shrinkable(&inode->i_data))
        return;

    if (list_lru_add_obj(&inode->i_sb->s_inode_lru, &inode->i_lru))
        this_cpu_inc(nr_unused);
    else if (rotate)
        inode->i_state |= I_REFERENCED;
}

/*
 * Add inode to LRU if needed (inode is unused and clean).
 *
 * Needs inode->i_lock held.
 */
void inode_add_lru(struct inode *inode)
{
    __inode_add_lru(inode, false);
}

/**
 * iget_locked - obtain an inode from a mounted file system
 * @sb:     super block of file system
 * @ino:    inode number to get
 *
 * Search for the inode specified by @ino in the inode cache and if present
 * return it with an increased reference count. This is for file systems
 * where the inode number is sufficient for unique identification of an inode.
 *
 * If the inode is not in cache, allocate a new inode and return it locked,
 * hashed, and with the I_NEW flag set.  The file system gets to fill it in
 * before unlocking it via unlock_new_inode().
 */
struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
    struct hlist_head *head = inode_hashtable + hash(sb, ino);
    struct inode *inode;
again:
    inode = find_inode_fast(sb, head, ino, false);
    if (inode) {
        if (IS_ERR(inode))
            return NULL;
        wait_on_inode(inode);
        if (unlikely(inode_unhashed(inode))) {
            iput(inode);
            goto again;
        }
        return inode;
    }

    inode = alloc_inode(sb);
    if (inode) {
        struct inode *old;

        spin_lock(&inode_hash_lock);
        /* We released the lock, so.. */
        old = find_inode_fast(sb, head, ino, true);
        if (!old) {
            inode->i_ino = ino;
            spin_lock(&inode->i_lock);
            inode->i_state = I_NEW;
            hlist_add_head_rcu(&inode->i_hash, head);
            spin_unlock(&inode->i_lock);
            inode_sb_list_add(inode);
            spin_unlock(&inode_hash_lock);

            /* Return the locked inode with I_NEW set, the
             * caller is responsible for filling in the contents
             */
            return inode;
        }

        PANIC("stage1");
    }

    PANIC("");
}

/**
 * set_nlink - directly set an inode's link count
 * @inode: inode
 * @nlink: new nlink (should be non-zero)
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.
 */
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

/**
 * file_modified_flags - handle mandated vfs changes when modifying a file
 * @file: file that was modified
 * @flags: kiocb flags
 *
 * When file has been modified ensure that special
 * file privileges are removed and time settings are updated.
 *
 * If IOCB_NOWAIT is set, special file privileges will not be removed and
 * time settings will not be updated. It will return -EAGAIN.
 *
 * Context: Caller must hold the file's inode lock.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int file_modified_flags(struct file *file, int flags)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

/**
 * file_modified - handle mandated vfs changes when modifying a file
 * @file: file that was modified
 *
 * When file has been modified ensure that special
 * file privileges are removed and time settings are updated.
 *
 * Context: Caller must hold the file's inode lock.
 *
 * Return: 0 on success, negative errno on failure.
 */
int file_modified(struct file *file)
{
    return file_modified_flags(file, 0);
}

/*
 * inode_set_flags - atomically set some inode flags
 *
 * Note: the caller should be holding i_mutex, or else be sure that
 * they have exclusive access to the inode structure (i.e., while the
 * inode is being instantiated).  The reason for the cmpxchg() loop
 * --- which wouldn't be necessary if all code paths which modify
 * i_flags actually followed this rule, is that there is at least one
 * code path which doesn't today so we use cmpxchg() out of an abundance
 * of caution.
 *
 * In the long run, i_mutex is overkill, and we should probably look
 * at using the i_lock spinlock to protect i_flags, and then make sure
 * it is so documented in include/linux/fs.h and that all code follows
 * the locking convention!!
 */
void inode_set_flags(struct inode *inode, unsigned int flags,
             unsigned int mask)
{
    WARN_ON_ONCE(flags & ~mask);
    set_mask_bits(&inode->i_flags, mask, flags);
}

/**
 * unlock_new_inode - clear the I_NEW state and wake up any waiters
 * @inode:  new inode to unlock
 *
 * Called when the inode is fully initialised to clear the new state of the
 * inode and wake up anyone waiting for the inode to finish initialisation.
 */
void unlock_new_inode(struct inode *inode)
{
    lockdep_annotate_inode_mutex_key(inode);
    spin_lock(&inode->i_lock);
    WARN_ON(!(inode->i_state & I_NEW));
    inode->i_state &= ~I_NEW & ~I_CREATING;
    /*
     * Pairs with the barrier in prepare_to_wait_event() to make sure
     * ___wait_var_event() either sees the bit cleared or
     * waitqueue_active() check in wake_up_var() sees the waiter.
     */
    smp_mb();
    inode_wake_up_bit(inode, __I_NEW);
    spin_unlock(&inode->i_lock);
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

void touch_atime(const struct path *path)
{
    pr_err("%s: No impl.", __func__);
#if 0
    struct vfsmount *mnt = path->mnt;
    struct inode *inode = d_inode(path->dentry);

    if (!atime_needs_update(path, inode))
        return;

    if (!sb_start_write_trylock(inode->i_sb))
        return;

    if (mnt_get_write_access(mnt) != 0)
        goto skip_update;
    /*
     * File systems can error out when updating inodes if they need to
     * allocate new space to modify an inode (such is the case for
     * Btrfs), but since we touch atime while walking down the path we
     * really don't care if we failed to update the atime of the file,
     * so just ignore the return value.
     * We may also fail on filesystems that have the ability to make parts
     * of the fs read only, e.g. subvolumes in Btrfs.
     */
    inode_update_time(inode, S_ATIME);
    mnt_put_write_access(mnt);
skip_update:
    sb_end_write(inode->i_sb);
#endif
}

/**
 * inode_init_owner - Init uid,gid,mode for new inode according to posix standards
 * @idmap: idmap of the mount the inode was created from
 * @inode: New inode
 * @dir: Directory inode
 * @mode: mode of the new inode
 *
 * If the inode has been created through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions
 * and initializing i_uid and i_gid. On non-idmapped mounts or if permission
 * checking is to be performed on the raw inode simply pass @nop_mnt_idmap.
 */
void inode_init_owner(struct mnt_idmap *idmap, struct inode *inode,
              const struct inode *dir, umode_t mode)
{
#if 0
    inode_fsuid_set(inode, idmap);
    if (dir && dir->i_mode & S_ISGID) {
        inode->i_gid = dir->i_gid;

        /* Directories are special, and always inherit S_ISGID */
        if (S_ISDIR(mode))
            mode |= S_ISGID;
    } else
        inode_fsgid_set(inode, idmap);
    inode->i_mode = mode;
#endif
    pr_err("%s: No impl.", __func__);
}

int insert_inode_locked(struct inode *inode)
{
    struct super_block *sb = inode->i_sb;
    ino_t ino = inode->i_ino;
    struct hlist_head *head = inode_hashtable + hash(sb, ino);

    while (1) {
        struct inode *old = NULL;
        spin_lock(&inode_hash_lock);
        hlist_for_each_entry(old, head, i_hash) {
            if (old->i_ino != ino)
                continue;
            if (old->i_sb != sb)
                continue;
            spin_lock(&old->i_lock);
            if (old->i_state & (I_FREEING|I_WILL_FREE)) {
                spin_unlock(&old->i_lock);
                continue;
            }
            break;
        }
        if (likely(!old)) {
            spin_lock(&inode->i_lock);
            inode->i_state |= I_NEW | I_CREATING;
            hlist_add_head_rcu(&inode->i_hash, head);
            spin_unlock(&inode->i_lock);
            spin_unlock(&inode_hash_lock);
            return 0;
        }
        if (unlikely(old->i_state & I_CREATING)) {
            spin_unlock(&old->i_lock);
            spin_unlock(&inode_hash_lock);
            return -EBUSY;
        }
        __iget(old);
        spin_unlock(&old->i_lock);
        spin_unlock(&inode_hash_lock);
        wait_on_inode(old);
        if (unlikely(!inode_unhashed(old))) {
            iput(old);
            return -EBUSY;
        }
        iput(old);

        PANIC("LOOP");
    }
    PANIC("");
}

/*
 * Initialize the waitqueues and inode hash table.
 */
void __init inode_init_early(void)
{
    /* If hashes are distributed across NUMA nodes, defer
     * hash allocation until vmalloc space is available.
     */
    if (hashdist)
        return;

    inode_hashtable =
        alloc_large_system_hash("Inode-cache",
                    sizeof(struct hlist_head),
                    ihash_entries,
                    14,
                    HASH_EARLY | HASH_ZERO,
                    &i_hash_shift,
                    &i_hash_mask,
                    0,
                    0);
}

void __init inode_init(void)
{
    /* inode slab cache */
    inode_cachep = kmem_cache_create("inode_cache",
                     sizeof(struct inode),
                     0,
                     (SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|
                     SLAB_ACCOUNT),
                     init_once);

    /* Hash may have been set up in inode_init_early */
    if (!hashdist)
        return;

    inode_hashtable =
        alloc_large_system_hash("Inode-cache",
                    sizeof(struct hlist_head),
                    ihash_entries,
                    14,
                    HASH_ZERO,
                    &i_hash_shift,
                    &i_hash_mask,
                    0,
                    0);
}
