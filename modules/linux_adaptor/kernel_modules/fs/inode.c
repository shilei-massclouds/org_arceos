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
