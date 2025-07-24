#include <linux/ratelimit.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/export.h>
#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/memblock.h>
#include <linux/bit_spinlock.h>
#include <linux/rculist_bl.h>
#include <linux/list_lru.h>
#include "internal.h"
#include "mount.h"

#include <asm/runtime-const.h>

#include "../adaptor.h"

const struct qstr empty_name = QSTR_INIT("", 0);
const struct qstr slash_name = QSTR_INIT("/", 1);
const struct qstr dotdot_name = QSTR_INIT("..", 2);

struct external_name {
    union {
        atomic_t count;
        struct rcu_head head;
    } u;
    unsigned char name[];
};

static inline struct external_name *external_name(struct dentry *dentry)
{
    return container_of(dentry->d_name.name, struct external_name, name[0]);
}

static inline int dname_external(const struct dentry *dentry)
{
    return dentry->d_name.name != dentry->d_iname;
}

/* SLAB cache for __getname() consumers */
struct kmem_cache *names_cachep __ro_after_init;

static struct kmem_cache *dentry_cache __ro_after_init;

static DEFINE_PER_CPU(long, nr_dentry);
static DEFINE_PER_CPU(long, nr_dentry_unused);
static DEFINE_PER_CPU(long, nr_dentry_negative);

struct dentry *d_make_root(struct inode *root_inode)
{
    struct dentry *res = NULL;

    if (root_inode) {
        res = d_alloc_anon(root_inode->i_sb);
        if (res)
            d_instantiate(res, root_inode);
        else
            iput(root_inode);
    }
    return res;
}

/**
 * __d_alloc    -   allocate a dcache entry
 * @sb: filesystem it will belong to
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
static struct dentry *__d_alloc(struct super_block *sb, const struct qstr *name)
{
    struct dentry *dentry;
    char *dname;
    int err;

    dentry = kmem_cache_alloc_lru(dentry_cache, &sb->s_dentry_lru,
                      GFP_KERNEL);
    if (!dentry)
        return NULL;

    /*
     * We guarantee that the inline name is always NUL-terminated.
     * This way the memcpy() done by the name switching in rename
     * will still always have a NUL at the end, even if we might
     * be overwriting an internal NUL character
     */
    dentry->d_iname[DNAME_INLINE_LEN-1] = 0;
    if (unlikely(!name)) {
        name = &slash_name;
        dname = dentry->d_iname;
    } else if (name->len > DNAME_INLINE_LEN-1) {
        size_t size = offsetof(struct external_name, name[1]);
        struct external_name *p = kmalloc(size + name->len,
                          GFP_KERNEL_ACCOUNT |
                          __GFP_RECLAIMABLE);
        if (!p) {
            kmem_cache_free(dentry_cache, dentry);
            return NULL;
        }
        atomic_set(&p->u.count, 1);
        dname = p->name;
    } else  {
        dname = dentry->d_iname;
    }

    dentry->d_name.len = name->len;
    dentry->d_name.hash = name->hash;
    memcpy(dname, name->name, name->len);
    dname[name->len] = 0;

    /* Make sure we always see the terminating NUL character */
    smp_store_release(&dentry->d_name.name, dname); /* ^^^ */
    dentry->d_lockref.count = 1;
    dentry->d_flags = 0;
    spin_lock_init(&dentry->d_lock);
    seqcount_spinlock_init(&dentry->d_seq, &dentry->d_lock);
    dentry->d_inode = NULL;
    dentry->d_parent = dentry;
    dentry->d_sb = sb;
    dentry->d_op = NULL;
    dentry->d_fsdata = NULL;
    INIT_HLIST_BL_NODE(&dentry->d_hash);
    INIT_LIST_HEAD(&dentry->d_lru);
    INIT_HLIST_HEAD(&dentry->d_children);
    INIT_HLIST_NODE(&dentry->d_u.d_alias);
    INIT_HLIST_NODE(&dentry->d_sib);
    d_set_d_op(dentry, dentry->d_sb->s_d_op);

    if (dentry->d_op && dentry->d_op->d_init) {
        err = dentry->d_op->d_init(dentry);
        if (err) {
            if (dname_external(dentry))
                kfree(external_name(dentry));
            kmem_cache_free(dentry_cache, dentry);
            return NULL;
        }
    }

    this_cpu_inc(nr_dentry);

    return dentry;
}

void d_set_d_op(struct dentry *dentry, const struct dentry_operations *op)
{
    WARN_ON_ONCE(dentry->d_op);
    WARN_ON_ONCE(dentry->d_flags & (DCACHE_OP_HASH  |
                DCACHE_OP_COMPARE   |
                DCACHE_OP_REVALIDATE    |
                DCACHE_OP_WEAK_REVALIDATE   |
                DCACHE_OP_DELETE    |
                DCACHE_OP_REAL));
    dentry->d_op = op;
    if (!op)
        return;
    if (op->d_hash)
        dentry->d_flags |= DCACHE_OP_HASH;
    if (op->d_compare)
        dentry->d_flags |= DCACHE_OP_COMPARE;
    if (op->d_revalidate)
        dentry->d_flags |= DCACHE_OP_REVALIDATE;
    if (op->d_weak_revalidate)
        dentry->d_flags |= DCACHE_OP_WEAK_REVALIDATE;
    if (op->d_delete)
        dentry->d_flags |= DCACHE_OP_DELETE;
    if (op->d_prune)
        dentry->d_flags |= DCACHE_OP_PRUNE;
    if (op->d_real)
        dentry->d_flags |= DCACHE_OP_REAL;

}

struct dentry *d_alloc_anon(struct super_block *sb)
{
    return __d_alloc(sb, NULL);
}

static unsigned d_flags_for_inode(struct inode *inode)
{
    unsigned add_flags = DCACHE_REGULAR_TYPE;

    if (!inode)
        return DCACHE_MISS_TYPE;

    if (S_ISDIR(inode->i_mode)) {
        add_flags = DCACHE_DIRECTORY_TYPE;
        if (unlikely(!(inode->i_opflags & IOP_LOOKUP))) {
            if (unlikely(!inode->i_op->lookup))
                add_flags = DCACHE_AUTODIR_TYPE;
            else
                inode->i_opflags |= IOP_LOOKUP;
        }
        goto type_determined;
    }

    if (unlikely(!(inode->i_opflags & IOP_NOFOLLOW))) {
        if (unlikely(inode->i_op->get_link)) {
            add_flags = DCACHE_SYMLINK_TYPE;
            goto type_determined;
        }
        inode->i_opflags |= IOP_NOFOLLOW;
    }

    if (unlikely(!S_ISREG(inode->i_mode)))
        add_flags = DCACHE_SPECIAL_TYPE;

type_determined:
    if (unlikely(IS_AUTOMOUNT(inode)))
        add_flags |= DCACHE_NEED_AUTOMOUNT;
    return add_flags;
}

static inline void __d_set_inode_and_type(struct dentry *dentry,
                      struct inode *inode,
                      unsigned type_flags)
{
    unsigned flags;

    dentry->d_inode = inode;
    flags = READ_ONCE(dentry->d_flags);
    flags &= ~DCACHE_ENTRY_TYPE;
    flags |= type_flags;
    smp_store_release(&dentry->d_flags, flags);
}

static void __d_instantiate(struct dentry *dentry, struct inode *inode)
{
    unsigned add_flags = d_flags_for_inode(inode);
    WARN_ON(d_in_lookup(dentry));

    spin_lock(&dentry->d_lock);
    /*
     * The negative counter only tracks dentries on the LRU. Don't dec if
     * d_lru is on another list.
     */
    if ((dentry->d_flags &
         (DCACHE_LRU_LIST|DCACHE_SHRINK_LIST)) == DCACHE_LRU_LIST)
        this_cpu_dec(nr_dentry_negative);
    hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry);
    raw_write_seqcount_begin(&dentry->d_seq);
    __d_set_inode_and_type(dentry, inode, add_flags);
    raw_write_seqcount_end(&dentry->d_seq);
    fsnotify_update_flags(dentry);
    spin_unlock(&dentry->d_lock);
}

/**
 * d_instantiate - fill in inode information for a dentry
 * @entry: dentry to complete
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry.
 *
 * This turns negative dentries into productive full members
 * of society.
 *
 * NOTE! This assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */

void d_instantiate(struct dentry *entry, struct inode * inode)
{
    BUG_ON(!hlist_unhashed(&entry->d_u.d_alias));
    if (inode) {
        //security_d_instantiate(entry, inode);
        spin_lock(&inode->i_lock);
        __d_instantiate(entry, inode);
        spin_unlock(&inode->i_lock);
    }
}

/*
 * This is dput
 *
 * This is complicated by the fact that we do not want to put
 * dentries that are no longer on any hash chain on the unused
 * list: we'd much rather just get rid of them immediately.
 *
 * However, that implies that we have to traverse the dentry
 * tree upwards to the parents which might _also_ now be
 * scheduled for deletion (it may have been only waiting for
 * its last child to go away).
 *
 * This tail recursion is done by hand as we don't want to depend
 * on the compiler to always get this right (gcc generally doesn't).
 * Real recursion would eat up our stack space.
 */

/*
 * dput - release a dentry
 * @dentry: dentry to release
 *
 * Release a dentry. This will drop the usage count and if appropriate
 * call the dentry unlink method as well as removing it from the queues and
 * releasing its resources. If the parent dentries were scheduled for release
 * they too may now get deleted.
 */
void dput(struct dentry *dentry)
{
    if (!dentry)
        return;

    pr_err("%s: No impl.", __func__);
}

static void __init dcache_init(void)
{
    /*
     * A constructor could be added for stable state like the lists,
     * but it is probably not worth it because of the cache nature
     * of the dcache.
     */
    dentry_cache = KMEM_CACHE_USERCOPY(dentry,
        SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_ACCOUNT,
        d_iname);

    /* Hash may have been set up in dcache_init_early */
    if (!hashdist)
        return;

#if 0
    dentry_hashtable =
        alloc_large_system_hash("Dentry cache",
                    sizeof(struct hlist_bl_head),
                    dhash_entries,
                    13,
                    HASH_ZERO,
                    &d_hash_shift,
                    NULL,
                    0,
                    0);
    d_hash_shift = 32 - d_hash_shift;

    runtime_const_init(shift, d_hash_shift);
    runtime_const_init(ptr, dentry_hashtable);
#endif

    PANIC("");
}

void __init vfs_caches_init(void)
{
    names_cachep = kmem_cache_create_usercopy("names_cache", PATH_MAX, 0,
            SLAB_HWCACHE_ALIGN|SLAB_PANIC, 0, PATH_MAX, NULL);

    dcache_init();
    inode_init();
    //files_init();
    //files_maxfiles_init();
    mnt_init();
    bdev_cache_init();
    //chrdev_init();
}
