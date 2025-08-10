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

__cacheline_aligned_in_smp DEFINE_SEQLOCK(rename_lock);

/*
 * This is the single most critical data structure when it comes
 * to the dcache: the hashtable for lookups. Somebody should try
 * to make this good - I've just made it work.
 *
 * This hash-function tries to avoid losing too many bits of hash
 * information, yet avoid using a prime hash-size or similar.
 *
 * Marking the variables "used" ensures that the compiler doesn't
 * optimize them away completely on architectures with runtime
 * constant infrastructure, this allows debuggers to see their
 * values. But updating these values has no effect on those arches.
 */

static unsigned int d_hash_shift __ro_after_init __used;

static struct hlist_bl_head *dentry_hashtable __ro_after_init __used;

static inline struct hlist_bl_head *d_hash(unsigned long hashlen)
{
    return runtime_const_ptr(dentry_hashtable) +
        runtime_const_shift_right_32(hashlen, d_hash_shift);
}

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

/**
 * d_ancestor - search for an ancestor
 * @p1: ancestor dentry
 * @p2: child dentry
 *
 * Returns the ancestor dentry of p2 which is a child of p1, if p1 is
 * an ancestor of p2, else NULL.
 */
struct dentry *d_ancestor(struct dentry *p1, struct dentry *p2)
{
    struct dentry *p;

    for (p = p2; !IS_ROOT(p); p = p->d_parent) {
        if (p->d_parent == p1)
            return p;
    }
    return NULL;
}

/*
 * This is __d_lookup_rcu() when the parent dentry has
 * DCACHE_OP_COMPARE, which makes things much nastier.
 */
static noinline struct dentry *__d_lookup_rcu_op_compare(
    const struct dentry *parent,
    const struct qstr *name,
    unsigned *seqp)
{
    PANIC("");
}

/**
 * __d_lookup_rcu - search for a dentry (racy, store-free)
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * @seqp: returns d_seq value at the point where the dentry was found
 * Returns: dentry, or NULL
 *
 * __d_lookup_rcu is the dcache lookup function for rcu-walk name
 * resolution (store-free path walking) design described in
 * Documentation/filesystems/path-lookup.txt.
 *
 * This is not to be used outside core vfs.
 *
 * __d_lookup_rcu must only be used in rcu-walk mode, ie. with vfsmount lock
 * held, and rcu_read_lock held. The returned dentry must not be stored into
 * without taking d_lock and checking d_seq sequence count against @seq
 * returned here.
 *
 * Alternatively, __d_lookup_rcu may be called again to look up the child of
 * the returned dentry, so long as its parent's seqlock is checked after the
 * child is looked up. Thus, an interlocking stepping of sequence lock checks
 * is formed, giving integrity down the path walk.
 *
 * NOTE! The caller *has* to check the resulting dentry against the sequence
 * number we've returned before using any of the resulting dentry state!
 */
struct dentry *__d_lookup_rcu(const struct dentry *parent,
                const struct qstr *name,
                unsigned *seqp)
{
    u64 hashlen = name->hash_len;
    const unsigned char *str = name->name;
    struct hlist_bl_head *b = d_hash(hashlen);
    struct hlist_bl_node *node;
    struct dentry *dentry;

    /*
     * Note: There is significant duplication with __d_lookup_rcu which is
     * required to prevent single threaded performance regressions
     * especially on architectures where smp_rmb (in seqcounts) are costly.
     * Keep the two functions in sync.
     */

    if (unlikely(parent->d_flags & DCACHE_OP_COMPARE))
        return __d_lookup_rcu_op_compare(parent, name, seqp);

    /*
     * The hash list is protected using RCU.
     *
     * Carefully use d_seq when comparing a candidate dentry, to avoid
     * races with d_move().
     *
     * It is possible that concurrent renames can mess up our list
     * walk here and result in missing our dentry, resulting in the
     * false-negative result. d_lookup() protects against concurrent
     * renames using rename_lock seqlock.
     *
     * See Documentation/filesystems/path-lookup.txt for more details.
     */
    hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {
        PANIC("LOOP");
    }
    return NULL;
}

/*
 * The DCACHE_LRU_LIST bit is set whenever the 'd_lru' entry
 * is in use - which includes both the "real" per-superblock
 * LRU list _and_ the DCACHE_SHRINK_LIST use.
 *
 * The DCACHE_SHRINK_LIST bit is set whenever the dentry is
 * on the shrink list (ie not on the superblock LRU list).
 *
 * The per-cpu "nr_dentry_unused" counters are updated with
 * the DCACHE_LRU_LIST bit.
 *
 * The per-cpu "nr_dentry_negative" counters are only updated
 * when deleted from or added to the per-superblock LRU list, not
 * from/to the shrink list. That is to avoid an unneeded dec/inc
 * pair when moving from LRU to shrink list in select_collect().
 *
 * These helper functions make sure we always follow the
 * rules. d_lock must be held by the caller.
 */
#define D_FLAG_VERIFY(dentry,x) WARN_ON_ONCE(((dentry)->d_flags & (DCACHE_LRU_LIST | DCACHE_SHRINK_LIST)) != (x))
static void d_lru_add(struct dentry *dentry)
{
    D_FLAG_VERIFY(dentry, 0);
    dentry->d_flags |= DCACHE_LRU_LIST;
    this_cpu_inc(nr_dentry_unused);
    if (d_is_negative(dentry))
        this_cpu_inc(nr_dentry_negative);
    WARN_ON_ONCE(!list_lru_add_obj(
            &dentry->d_sb->s_dentry_lru, &dentry->d_lru));
}

static void d_lru_del(struct dentry *dentry)
{
    D_FLAG_VERIFY(dentry, DCACHE_LRU_LIST);
    dentry->d_flags &= ~DCACHE_LRU_LIST;
    this_cpu_dec(nr_dentry_unused);
    if (d_is_negative(dentry))
        this_cpu_dec(nr_dentry_negative);
    WARN_ON_ONCE(!list_lru_del_obj(
            &dentry->d_sb->s_dentry_lru, &dentry->d_lru));
}

#define IN_LOOKUP_SHIFT 10
static struct hlist_bl_head in_lookup_hashtable[1 << IN_LOOKUP_SHIFT];

static inline struct hlist_bl_head *in_lookup_hash(const struct dentry *parent,
                    unsigned int hash)
{
    hash += (unsigned long) parent / L1_CACHE_BYTES;
    return in_lookup_hashtable + hash_32(hash, IN_LOOKUP_SHIFT);
}

/*
 * - Unhash the dentry
 * - Retrieve and clear the waitqueue head in dentry
 * - Return the waitqueue head
 */
static wait_queue_head_t *__d_lookup_unhash(struct dentry *dentry)
{
    wait_queue_head_t *d_wait;
    struct hlist_bl_head *b;

    lockdep_assert_held(&dentry->d_lock);

    b = in_lookup_hash(dentry->d_parent, dentry->d_name.hash);
    hlist_bl_lock(b);
    dentry->d_flags &= ~DCACHE_PAR_LOOKUP;
    __hlist_bl_del(&dentry->d_u.d_in_lookup_hash);
    d_wait = dentry->d_wait;
    dentry->d_wait = NULL;
    hlist_bl_unlock(b);
    INIT_HLIST_NODE(&dentry->d_u.d_alias);
    INIT_LIST_HEAD(&dentry->d_lru);
    return d_wait;
}

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

static struct dentry * __d_find_any_alias(struct inode *inode)
{
    struct dentry *alias;

    if (hlist_empty(&inode->i_dentry))
        return NULL;
    alias = hlist_entry(inode->i_dentry.first, struct dentry, d_u.d_alias);
    lockref_get(&alias->d_lockref);
    return alias;
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
 * Decide if dentry is worth retaining.  Usually this is called with dentry
 * locked; if not locked, we are more limited and might not be able to tell
 * without a lock.  False in this case means "punt to locked path and recheck".
 *
 * In case we aren't locked, these predicates are not "stable". However, it is
 * sufficient that at some point after we dropped the reference the dentry was
 * hashed and the flags had the proper value. Other dentry users may have
 * re-gotten a reference to the dentry and change that, but our work is done -
 * we can leave the dentry around with a zero refcount.
 */
static inline bool retain_dentry(struct dentry *dentry, bool locked)
{
    unsigned int d_flags;

    smp_rmb();
    d_flags = READ_ONCE(dentry->d_flags);

    // Unreachable? Nobody would be able to look it up, no point retaining
    if (unlikely(d_unhashed(dentry)))
        return false;

    // Same if it's disconnected
    if (unlikely(d_flags & DCACHE_DISCONNECTED))
        return false;

    // ->d_delete() might tell us not to bother, but that requires
    // ->d_lock; can't decide without it
    if (unlikely(d_flags & DCACHE_OP_DELETE)) {
        if (!locked || dentry->d_op->d_delete(dentry))
            return false;
    }

    // Explicitly told not to bother
    if (unlikely(d_flags & DCACHE_DONTCACHE))
        return false;

    // At this point it looks like we ought to keep it.  We also might
    // need to do something - put it on LRU if it wasn't there already
    // and mark it referenced if it was on LRU, but not marked yet.
    // Unfortunately, both actions require ->d_lock, so in lockless
    // case we'd have to punt rather than doing those.
    if (unlikely(!(d_flags & DCACHE_LRU_LIST))) {
        if (!locked)
            return false;
        d_lru_add(dentry);
    } else if (unlikely(!(d_flags & DCACHE_REFERENCED))) {
        if (!locked)
            return false;
        dentry->d_flags |= DCACHE_REFERENCED;
    }
    return true;
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
 * Try to do a lockless dput(), and return whether that was successful.
 *
 * If unsuccessful, we return false, having already taken the dentry lock.
 * In that case refcount is guaranteed to be zero and we have already
 * decided that it's not worth keeping around.
 *
 * The caller needs to hold the RCU read lock, so that the dentry is
 * guaranteed to stay around even if the refcount goes down to zero!
 */
static inline bool fast_dput(struct dentry *dentry)
{
    int ret;

    /*
     * try to decrement the lockref optimistically.
     */
    ret = lockref_put_return(&dentry->d_lockref);

    /*
     * If the lockref_put_return() failed due to the lock being held
     * by somebody else, the fast path has failed. We will need to
     * get the lock, and then check the count again.
     */
    if (unlikely(ret < 0)) {
        spin_lock(&dentry->d_lock);
        if (WARN_ON_ONCE(dentry->d_lockref.count <= 0)) {
            spin_unlock(&dentry->d_lock);
            return true;
        }
        dentry->d_lockref.count--;
        goto locked;
    }

    /*
     * If we weren't the last ref, we're done.
     */
    if (ret)
        return true;

    /*
     * Can we decide that decrement of refcount is all we needed without
     * taking the lock?  There's a very common case when it's all we need -
     * dentry looks like it ought to be retained and there's nothing else
     * to do.
     */
    if (retain_dentry(dentry, false))
        return true;

    /*
     * Either not worth retaining or we can't tell without the lock.
     * Get the lock, then.  We've already decremented the refcount to 0,
     * but we'll need to re-check the situation after getting the lock.
     */
    spin_lock(&dentry->d_lock);

    PANIC("");
    /*
     * Did somebody else grab a reference to it in the meantime, and
     * we're no longer the last user after all? Alternatively, somebody
     * else could have killed it and marked it dead. Either way, we
     * don't need to do anything else.
     */
locked:
    if (dentry->d_lockref.count || retain_dentry(dentry, true)) {
        spin_unlock(&dentry->d_lock);
        return true;
    }
    return false;
}

/*
 * Lock a dentry for feeding it to __dentry_kill().
 * Called under rcu_read_lock() and dentry->d_lock; the former
 * guarantees that nothing we access will be freed under us.
 * Note that dentry is *not* protected from concurrent dentry_kill(),
 * d_delete(), etc.
 *
 * Return false if dentry is busy.  Otherwise, return true and have
 * that dentry's inode locked.
 */

static bool lock_for_kill(struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;

    if (unlikely(dentry->d_lockref.count))
        return false;

    if (!inode || likely(spin_trylock(&inode->i_lock)))
        return true;

    do {
        spin_unlock(&dentry->d_lock);
        spin_lock(&inode->i_lock);
        spin_lock(&dentry->d_lock);
        if (likely(inode == dentry->d_inode))
            break;
        spin_unlock(&inode->i_lock);
        inode = dentry->d_inode;
    } while (inode);
    if (likely(!dentry->d_lockref.count))
        return true;
    if (inode)
        spin_unlock(&inode->i_lock);
    return false;
}

static void ___d_drop(struct dentry *dentry)
{
    struct hlist_bl_head *b;
    /*
     * Hashed dentries are normally on the dentry hashtable,
     * with the exception of those newly allocated by
     * d_obtain_root, which are always IS_ROOT:
     */
    if (unlikely(IS_ROOT(dentry)))
        b = &dentry->d_sb->s_roots;
    else
        b = d_hash(dentry->d_name.hash);

    hlist_bl_lock(b);
    __hlist_bl_del(&dentry->d_hash);
    hlist_bl_unlock(b);
}

void __d_drop(struct dentry *dentry)
{
    if (!d_unhashed(dentry)) {
        ___d_drop(dentry);
        dentry->d_hash.pprev = NULL;
        write_seqcount_invalidate(&dentry->d_seq);
    }
}

/*
 * Release the dentry's inode, using the filesystem
 * d_iput() operation if defined.
 */
static inline void __d_clear_type_and_inode(struct dentry *dentry)
{
    unsigned flags = READ_ONCE(dentry->d_flags);

    flags &= ~DCACHE_ENTRY_TYPE;
    WRITE_ONCE(dentry->d_flags, flags);
    dentry->d_inode = NULL;
    /*
     * The negative counter only tracks dentries on the LRU. Don't inc if
     * d_lru is on another list.
     */
    if ((flags & (DCACHE_LRU_LIST|DCACHE_SHRINK_LIST)) == DCACHE_LRU_LIST)
        this_cpu_inc(nr_dentry_negative);
}

static void dentry_unlink_inode(struct dentry * dentry)
    __releases(dentry->d_lock)
    __releases(dentry->d_inode->i_lock)
{
    struct inode *inode = dentry->d_inode;

    raw_write_seqcount_begin(&dentry->d_seq);
    __d_clear_type_and_inode(dentry);
    hlist_del_init(&dentry->d_u.d_alias);
    raw_write_seqcount_end(&dentry->d_seq);
    spin_unlock(&dentry->d_lock);
    spin_unlock(&inode->i_lock);
    if (!inode->i_nlink)
        fsnotify_inoderemove(inode);
    if (dentry->d_op && dentry->d_op->d_iput)
        dentry->d_op->d_iput(dentry, inode);
    else
        iput(inode);
}

static inline void dentry_unlist(struct dentry *dentry)
{
    struct dentry *next;
    /*
     * Inform d_walk() and shrink_dentry_list() that we are no longer
     * attached to the dentry tree
     */
    dentry->d_flags |= DCACHE_DENTRY_KILLED;
    if (unlikely(hlist_unhashed(&dentry->d_sib)))
        return;
    __hlist_del(&dentry->d_sib);
    /*
     * Cursors can move around the list of children.  While we'd been
     * a normal list member, it didn't matter - ->d_sib.next would've
     * been updated.  However, from now on it won't be and for the
     * things like d_walk() it might end up with a nasty surprise.
     * Normally d_walk() doesn't care about cursors moving around -
     * ->d_lock on parent prevents that and since a cursor has no children
     * of its own, we get through it without ever unlocking the parent.
     * There is one exception, though - if we ascend from a child that
     * gets killed as soon as we unlock it, the next sibling is found
     * using the value left in its ->d_sib.next.  And if _that_
     * pointed to a cursor, and cursor got moved (e.g. by lseek())
     * before d_walk() regains parent->d_lock, we'll end up skipping
     * everything the cursor had been moved past.
     *
     * Solution: make sure that the pointer left behind in ->d_sib.next
     * points to something that won't be moving around.  I.e. skip the
     * cursors.
     */
    while (dentry->d_sib.next) {
        next = hlist_entry(dentry->d_sib.next, struct dentry, d_sib);
        if (likely(!(next->d_flags & DCACHE_DENTRY_CURSOR)))
            break;
        dentry->d_sib.next = next->d_sib.next;
    }
}

static void __d_free(struct rcu_head *head)
{
    struct dentry *dentry = container_of(head, struct dentry, d_u.d_rcu);

    kmem_cache_free(dentry_cache, dentry);
}

static void __d_free_external(struct rcu_head *head)
{
    struct dentry *dentry = container_of(head, struct dentry, d_u.d_rcu);
    kfree(external_name(dentry));
    kmem_cache_free(dentry_cache, dentry);
}

static void dentry_free(struct dentry *dentry)
{
    WARN_ON(!hlist_unhashed(&dentry->d_u.d_alias));
    if (unlikely(dname_external(dentry))) {
        struct external_name *p = external_name(dentry);
        if (likely(atomic_dec_and_test(&p->u.count))) {
            call_rcu(&dentry->d_u.d_rcu, __d_free_external);
            return;
        }
    }
    /* if dentry was never visible to RCU, immediate free is OK */
    if (dentry->d_flags & DCACHE_NORCU)
        __d_free(&dentry->d_u.d_rcu);
    else
        call_rcu(&dentry->d_u.d_rcu, __d_free);
}

static struct dentry *__dentry_kill(struct dentry *dentry)
{
    struct dentry *parent = NULL;
    bool can_free = true;

    /*
     * The dentry is now unrecoverably dead to the world.
     */
    lockref_mark_dead(&dentry->d_lockref);

    /*
     * inform the fs via d_prune that this dentry is about to be
     * unhashed and destroyed.
     */
    if (dentry->d_flags & DCACHE_OP_PRUNE)
        dentry->d_op->d_prune(dentry);

    if (dentry->d_flags & DCACHE_LRU_LIST) {
        if (!(dentry->d_flags & DCACHE_SHRINK_LIST))
            d_lru_del(dentry);
    }

    /* if it was on the hash then remove it */
    __d_drop(dentry);
    if (dentry->d_inode)
        dentry_unlink_inode(dentry);
    else
        spin_unlock(&dentry->d_lock);
    this_cpu_dec(nr_dentry);
    if (dentry->d_op && dentry->d_op->d_release)
        dentry->d_op->d_release(dentry);

    cond_resched();
    /* now that it's negative, ->d_parent is stable */
    if (!IS_ROOT(dentry)) {
        parent = dentry->d_parent;
        spin_lock(&parent->d_lock);
    }
    spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
    dentry_unlist(dentry);
    if (dentry->d_flags & DCACHE_SHRINK_LIST)
        can_free = false;
    spin_unlock(&dentry->d_lock);
    if (likely(can_free))
        dentry_free(dentry);
    if (parent && --parent->d_lockref.count) {
        spin_unlock(&parent->d_lock);
        return NULL;
    }
    return parent;
}

struct dentry *d_alloc_parallel(struct dentry *parent,
                const struct qstr *name,
                wait_queue_head_t *wq)
{
    unsigned int hash = name->hash;
    struct hlist_bl_head *b = in_lookup_hash(parent, hash);
    struct hlist_bl_node *node;
    struct dentry *new = d_alloc(parent, name);
    struct dentry *dentry;
    unsigned seq, r_seq, d_seq;

    if (unlikely(!new))
        return ERR_PTR(-ENOMEM);

retry:
    rcu_read_lock();
    seq = smp_load_acquire(&parent->d_inode->i_dir_seq);
    r_seq = read_seqbegin(&rename_lock);
    dentry = __d_lookup_rcu(parent, name, &d_seq);
    if (unlikely(dentry)) {
        if (!lockref_get_not_dead(&dentry->d_lockref)) {
            rcu_read_unlock();
            goto retry;
        }
        if (read_seqcount_retry(&dentry->d_seq, d_seq)) {
            rcu_read_unlock();
            dput(dentry);
            goto retry;
        }
        rcu_read_unlock();
        dput(new);
        return dentry;
    }
    if (unlikely(read_seqretry(&rename_lock, r_seq))) {
        rcu_read_unlock();
        goto retry;
    }

    if (unlikely(seq & 1)) {
        rcu_read_unlock();
        goto retry;
    }

    hlist_bl_lock(b);
    if (unlikely(READ_ONCE(parent->d_inode->i_dir_seq) != seq)) {
        hlist_bl_unlock(b);
        rcu_read_unlock();
        goto retry;
    }
    /*
     * No changes for the parent since the beginning of d_lookup().
     * Since all removals from the chain happen with hlist_bl_lock(),
     * any potential in-lookup matches are going to stay here until
     * we unlock the chain.  All fields are stable in everything
     * we encounter.
     */
    hlist_bl_for_each_entry(dentry, node, b, d_u.d_in_lookup_hash) {
        PANIC("LOOP");
    }
    rcu_read_unlock();
    /* we can't take ->d_lock here; it's OK, though. */
    new->d_flags |= DCACHE_PAR_LOOKUP;
    new->d_wait = wq;
    hlist_bl_add_head(&new->d_u.d_in_lookup_hash, b);
    hlist_bl_unlock(b);
    return new;
mismatch:
    spin_unlock(&dentry->d_lock);
    dput(dentry);
    goto retry;
}

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

    might_sleep();
    rcu_read_lock();
    if (likely(fast_dput(dentry))) {
        rcu_read_unlock();
        return;
    }
    while (lock_for_kill(dentry)) {
        rcu_read_unlock();
        dentry = __dentry_kill(dentry);
        printk("%s: step1\n", __func__);
        if (!dentry)
            return;
        printk("%s: step2\n", __func__);
        if (retain_dentry(dentry, true)) {
            spin_unlock(&dentry->d_lock);
            return;
        }
        rcu_read_lock();
    }
    rcu_read_unlock();
    spin_unlock(&dentry->d_lock);
}

/**
 * d_alloc_pseudo - allocate a dentry (for lookup-less filesystems)
 * @sb: the superblock
 * @name: qstr of the name
 *
 * For a filesystem that just pins its dentries in memory and never
 * performs lookups at all, return an unhashed IS_ROOT dentry.
 * This is used for pipes, sockets et.al. - the stuff that should
 * never be anyone's children or parents.  Unlike all other
 * dentries, these will not have RCU delay between dropping the
 * last reference and freeing them.
 *
 * The only user is alloc_file_pseudo() and that's what should
 * be considered a public interface.  Don't use directly.
 */
struct dentry *d_alloc_pseudo(struct super_block *sb, const struct qstr *name)
{
    static const struct dentry_operations anon_ops = {
        .d_dname = simple_dname
    };
    struct dentry *dentry = __d_alloc(sb, name);
    if (likely(dentry)) {
        dentry->d_flags |= DCACHE_NORCU;
        if (!sb->s_d_op)
            d_set_d_op(dentry, &anon_ops);
    }
    return dentry;
}

static inline unsigned start_dir_add(struct inode *dir)
{
    preempt_disable_nested();
    for (;;) {
        unsigned n = dir->i_dir_seq;
        if (!(n & 1) && cmpxchg(&dir->i_dir_seq, n, n + 1) == n)
            return n;
        cpu_relax();
    }
}

static inline void end_dir_add(struct inode *dir, unsigned int n,
                   wait_queue_head_t *d_wait)
{
    smp_store_release(&dir->i_dir_seq, n + 2);
    preempt_enable_nested();
    wake_up_all(d_wait);
}

static void __d_rehash(struct dentry *entry)
{
    struct hlist_bl_head *b = d_hash(entry->d_name.hash);

    hlist_bl_lock(b);
    hlist_bl_add_head_rcu(&entry->d_hash, b);
    hlist_bl_unlock(b);
}

/* inode->i_lock held if inode is non-NULL */

static inline void __d_add(struct dentry *dentry, struct inode *inode)
{
    wait_queue_head_t *d_wait;
    struct inode *dir = NULL;
    unsigned n;
    spin_lock(&dentry->d_lock);
    if (unlikely(d_in_lookup(dentry))) {
        dir = dentry->d_parent->d_inode;
        n = start_dir_add(dir);
        d_wait = __d_lookup_unhash(dentry);
    }
    if (inode) {
        unsigned add_flags = d_flags_for_inode(inode);
        hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry);
        raw_write_seqcount_begin(&dentry->d_seq);
        __d_set_inode_and_type(dentry, inode, add_flags);
        raw_write_seqcount_end(&dentry->d_seq);
        //fsnotify_update_flags(dentry);
    }
    __d_rehash(dentry);
    if (dir)
        end_dir_add(dir, n, d_wait);
    spin_unlock(&dentry->d_lock);
    if (inode)
        spin_unlock(&inode->i_lock);
}

static void copy_name(struct dentry *dentry, struct dentry *target)
{
    struct external_name *old_name = NULL;
    if (unlikely(dname_external(dentry)))
        old_name = external_name(dentry);
    if (unlikely(dname_external(target))) {
        atomic_inc(&external_name(target)->u.count);
        dentry->d_name = target->d_name;
    } else {
        memcpy(dentry->d_iname, target->d_name.name,
                target->d_name.len + 1);
        dentry->d_name.name = dentry->d_iname;
        dentry->d_name.hash_len = target->d_name.hash_len;
    }
    if (old_name && likely(atomic_dec_and_test(&old_name->u.count)))
        kfree_rcu(old_name, u.head);
}

static void swap_names(struct dentry *dentry, struct dentry *target)
{
    PANIC("");
}

/*
 * __d_move - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 * @exchange: exchange the two dentries
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way. Caller must hold
 * rename_lock, the i_mutex of the source and target directories,
 * and the sb->s_vfs_rename_mutex if they differ. See lock_rename().
 */
static void __d_move(struct dentry *dentry, struct dentry *target,
             bool exchange)
{
    struct dentry *old_parent, *p;
    wait_queue_head_t *d_wait;
    struct inode *dir = NULL;
    unsigned n;

    WARN_ON(!dentry->d_inode);
    if (WARN_ON(dentry == target))
        return;

    BUG_ON(d_ancestor(target, dentry));
    old_parent = dentry->d_parent;
    p = d_ancestor(old_parent, target);
    if (IS_ROOT(dentry)) {
        BUG_ON(p);
        spin_lock(&target->d_parent->d_lock);
    } else if (!p) {
        /* target is not a descendent of dentry->d_parent */
        spin_lock(&target->d_parent->d_lock);
        spin_lock_nested(&old_parent->d_lock, DENTRY_D_LOCK_NESTED);
    } else {
        BUG_ON(p == dentry);
        spin_lock(&old_parent->d_lock);
        if (p != target)
            spin_lock_nested(&target->d_parent->d_lock,
                    DENTRY_D_LOCK_NESTED);
    }
    spin_lock_nested(&dentry->d_lock, 2);
    spin_lock_nested(&target->d_lock, 3);

    if (unlikely(d_in_lookup(target))) {
        dir = target->d_parent->d_inode;
        n = start_dir_add(dir);
        d_wait = __d_lookup_unhash(target);
    }

    write_seqcount_begin(&dentry->d_seq);
    write_seqcount_begin_nested(&target->d_seq, DENTRY_D_LOCK_NESTED);

    /* unhash both */
    if (!d_unhashed(dentry))
        ___d_drop(dentry);
    if (!d_unhashed(target))
        ___d_drop(target);

    /* ... and switch them in the tree */
    dentry->d_parent = target->d_parent;
    if (!exchange) {
        copy_name(dentry, target);
        target->d_hash.pprev = NULL;
        dentry->d_parent->d_lockref.count++;
        if (dentry != old_parent) /* wasn't IS_ROOT */
            WARN_ON(!--old_parent->d_lockref.count);
    } else {
        target->d_parent = old_parent;
        swap_names(dentry, target);
        if (!hlist_unhashed(&target->d_sib))
            __hlist_del(&target->d_sib);
        hlist_add_head(&target->d_sib, &target->d_parent->d_children);
        __d_rehash(target);
        fsnotify_update_flags(target);
    }
    if (!hlist_unhashed(&dentry->d_sib))
        __hlist_del(&dentry->d_sib);
    hlist_add_head(&dentry->d_sib, &dentry->d_parent->d_children);
    __d_rehash(dentry);
    fsnotify_update_flags(dentry);
    fscrypt_handle_d_move(dentry);

    write_seqcount_end(&target->d_seq);
    write_seqcount_end(&dentry->d_seq);

    if (dir)
        end_dir_add(dir, n, d_wait);

    if (dentry->d_parent != old_parent)
        spin_unlock(&dentry->d_parent->d_lock);
    if (dentry != old_parent)
        spin_unlock(&old_parent->d_lock);
    spin_unlock(&target->d_lock);
    spin_unlock(&dentry->d_lock);
}

/*
 * This helper attempts to cope with remotely renamed directories
 *
 * It assumes that the caller is already holding
 * dentry->d_parent->d_inode->i_mutex, and rename_lock
 *
 * Note: If ever the locking in lock_rename() changes, then please
 * remember to update this too...
 */
static int __d_unalias(struct dentry *dentry, struct dentry *alias)
{
    struct mutex *m1 = NULL;
    struct rw_semaphore *m2 = NULL;
    int ret = -ESTALE;

    /* If alias and dentry share a parent, then no extra locks required */
    if (alias->d_parent == dentry->d_parent)
        goto out_unalias;

    /* See lock_rename() */
    if (!mutex_trylock(&dentry->d_sb->s_vfs_rename_mutex))
        goto out_err;
    m1 = &dentry->d_sb->s_vfs_rename_mutex;
    if (!inode_trylock_shared(alias->d_parent->d_inode))
        goto out_err;
    m2 = &alias->d_parent->d_inode->i_rwsem;
out_unalias:
    __d_move(alias, dentry, false);
    ret = 0;
out_err:
    if (m2)
        up_read(m2);
    if (m1)
        mutex_unlock(m1);
    return ret;
}

/**
 * d_splice_alias - splice a disconnected dentry into the tree if one exists
 * @inode:  the inode which may have a disconnected dentry
 * @dentry: a negative dentry which we want to point to the inode.
 *
 * If inode is a directory and has an IS_ROOT alias, then d_move that in
 * place of the given dentry and return it, else simply d_add the inode
 * to the dentry and return NULL.
 *
 * If a non-IS_ROOT directory is found, the filesystem is corrupt, and
 * we should error out: directories can't have multiple aliases.
 *
 * This is needed in the lookup routine of any filesystem that is exportable
 * (via knfsd) so that we can build dcache paths to directories effectively.
 *
 * If a dentry was found and moved, then it is returned.  Otherwise NULL
 * is returned.  This matches the expected return value of ->lookup.
 *
 * Cluster filesystems may call this function with a negative, hashed dentry.
 * In that case, we know that the inode will be a regular file, and also this
 * will only occur during atomic_open. So we need to check for the dentry
 * being already hashed only in the final case.
 */
struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry)
{
    if (IS_ERR(inode))
        return ERR_CAST(inode);

    BUG_ON(!d_unhashed(dentry));

    printk("%s: step1\n", __func__);
    if (!inode)
        goto out;

    //security_d_instantiate(dentry, inode);
    spin_lock(&inode->i_lock);
    if (S_ISDIR(inode->i_mode)) {
        struct dentry *new = __d_find_any_alias(inode);
        if (unlikely(new)) {
            /* The reference to new ensures it remains an alias */
            spin_unlock(&inode->i_lock);
            write_seqlock(&rename_lock);
            if (unlikely(d_ancestor(new, dentry))) {
                write_sequnlock(&rename_lock);
                dput(new);
                new = ERR_PTR(-ELOOP);
                pr_warn_ratelimited(
                    "VFS: Lookup of '%s' in %s %s"
                    " would have caused loop\n",
                    dentry->d_name.name,
                    inode->i_sb->s_type->name,
                    inode->i_sb->s_id);
            } else if (!IS_ROOT(new)) {
                struct dentry *old_parent = dget(new->d_parent);
                int err = __d_unalias(dentry, new);
                write_sequnlock(&rename_lock);
                if (err) {
                    dput(new);
                    new = ERR_PTR(err);
                }
                dput(old_parent);
            } else {
                __d_move(new, dentry, false);
                write_sequnlock(&rename_lock);
            }
            iput(inode);
            return new;
        }
    }
out:
    __d_add(dentry, inode);
    return NULL;
}

static __initdata unsigned long dhash_entries;

static void __init dcache_init_early(void)
{
    /* If hashes are distributed across NUMA nodes, defer
     * hash allocation until vmalloc space is available.
     */
    if (hashdist)
        return;

    dentry_hashtable =
        alloc_large_system_hash("Dentry cache",
                    sizeof(struct hlist_bl_head),
                    dhash_entries,
                    13,
                    HASH_EARLY | HASH_ZERO,
                    &d_hash_shift,
                    NULL,
                    0,
                    0);
    d_hash_shift = 32 - d_hash_shift;

    runtime_const_init(shift, d_hash_shift);
    runtime_const_init(ptr, dentry_hashtable);
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

/**
 * d_alloc  -   allocate a dcache entry
 * @parent: parent of entry to allocate
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
struct dentry *d_alloc(struct dentry * parent, const struct qstr *name)
{
    struct dentry *dentry = __d_alloc(parent->d_sb, name);
    if (!dentry)
        return NULL;
    spin_lock(&parent->d_lock);
    /*
     * don't need child lock because it is not subject
     * to concurrency here
     */
    dentry->d_parent = dget_dlock(parent);
    hlist_add_head(&dentry->d_sib, &parent->d_children);
    spin_unlock(&parent->d_lock);

    return dentry;
}

/*
 * This should be equivalent to d_instantiate() + unlock_new_inode(),
 * with lockdep-related part of unlock_new_inode() done before
 * anything else.  Use that instead of open-coding d_instantiate()/
 * unlock_new_inode() combinations.
 */
void d_instantiate_new(struct dentry *entry, struct inode *inode)
{
    BUG_ON(!hlist_unhashed(&entry->d_u.d_alias));
    BUG_ON(!inode);
    lockdep_annotate_inode_mutex_key(inode);
    //security_d_instantiate(entry, inode);
    spin_lock(&inode->i_lock);
    __d_instantiate(entry, inode);
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
 * __d_lookup - search for a dentry (racy)
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * Returns: dentry, or NULL
 *
 * __d_lookup is like d_lookup, however it may (rarely) return a
 * false-negative result due to unrelated rename activity.
 *
 * __d_lookup is slightly faster by avoiding rename_lock read seqlock,
 * however it must be used carefully, eg. with a following d_lookup in
 * the case of failure.
 *
 * __d_lookup callers must be commented.
 */
struct dentry *__d_lookup(const struct dentry *parent, const struct qstr *name)
{
    unsigned int hash = name->hash;
    struct hlist_bl_head *b = d_hash(hash);
    struct hlist_bl_node *node;
    struct dentry *found = NULL;
    struct dentry *dentry;

    /*
     * Note: There is significant duplication with __d_lookup_rcu which is
     * required to prevent single threaded performance regressions
     * especially on architectures where smp_rmb (in seqcounts) are costly.
     * Keep the two functions in sync.
     */

    /*
     * The hash list is protected using RCU.
     *
     * Take d_lock when comparing a candidate dentry, to avoid races
     * with d_move().
     *
     * It is possible that concurrent renames can mess up our list
     * walk here and result in missing our dentry, resulting in the
     * false-negative result. d_lookup() protects against concurrent
     * renames using rename_lock seqlock.
     *
     * See Documentation/filesystems/path-lookup.txt for more details.
     */
    rcu_read_lock();

    hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {

        PANIC("LOOP");
    }
    rcu_read_unlock();

    return found;
}

/**
 * d_lookup - search for a dentry
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * Returns: dentry, or NULL
 *
 * d_lookup searches the children of the parent dentry for the name in
 * question. If the dentry is found its reference count is incremented and the
 * dentry is returned. The caller must use dput to free the entry when it has
 * finished using it. %NULL is returned if the dentry does not exist.
 */
struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
{
    struct dentry *dentry;
    unsigned seq;

    do {
        seq = read_seqbegin(&rename_lock);
        dentry = __d_lookup(parent, name);
        if (dentry)
            break;
    } while (read_seqretry(&rename_lock, seq));
    return dentry;
}

void __d_lookup_unhash_wake(struct dentry *dentry)
{
    spin_lock(&dentry->d_lock);
    wake_up_all(__d_lookup_unhash(dentry));
    spin_unlock(&dentry->d_lock);
}

static void d_shrink_del(struct dentry *dentry)
{
    D_FLAG_VERIFY(dentry, DCACHE_SHRINK_LIST | DCACHE_LRU_LIST);
    list_del_init(&dentry->d_lru);
    dentry->d_flags &= ~(DCACHE_SHRINK_LIST | DCACHE_LRU_LIST);
    this_cpu_dec(nr_dentry_unused);
}

static inline void shrink_kill(struct dentry *victim)
{
    do {
        rcu_read_unlock();
        victim = __dentry_kill(victim);
        rcu_read_lock();
    } while (victim && lock_for_kill(victim));
    rcu_read_unlock();
    if (victim)
        spin_unlock(&victim->d_lock);
}

void shrink_dentry_list(struct list_head *list)
{
    while (!list_empty(list)) {
        struct dentry *dentry;

        dentry = list_entry(list->prev, struct dentry, d_lru);
        spin_lock(&dentry->d_lock);
        rcu_read_lock();
        if (!lock_for_kill(dentry)) {
            bool can_free;
            rcu_read_unlock();
            d_shrink_del(dentry);
            can_free = dentry->d_flags & DCACHE_DENTRY_KILLED;
            spin_unlock(&dentry->d_lock);
            if (can_free)
                dentry_free(dentry);
            continue;
        }
        d_shrink_del(dentry);
        shrink_kill(dentry);
    }
}

void __init vfs_caches_init_early(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(in_lookup_hashtable); i++)
        INIT_HLIST_BL_HEAD(&in_lookup_hashtable[i]);

    dcache_init_early();
    inode_init_early();
}

void __init vfs_caches_init(void)
{
    names_cachep = kmem_cache_create_usercopy("names_cache", PATH_MAX, 0,
            SLAB_HWCACHE_ALIGN|SLAB_PANIC, 0, PATH_MAX, NULL);

    dcache_init();
    inode_init();
    files_init();
    files_maxfiles_init();
    mnt_init();
    bdev_cache_init();
    //chrdev_init();
}
