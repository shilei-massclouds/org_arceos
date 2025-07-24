#include <linux/export.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/writeback.h>        /* for the emergency remount stuff */
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/backing-dev.h>
#include <linux/rculist_bl.h>
#include <linux/fscrypt.h>
#include <linux/fsnotify.h>
#include <linux/lockdep.h>
#include <linux/user_namespace.h>
#include <linux/fs_context.h>
#include <uapi/linux/mount.h>
#include "internal.h"

#include "../adaptor.h"

static LIST_HEAD(super_blocks);
static DEFINE_SPINLOCK(sb_lock);

static DEFINE_IDA(unnamed_dev_ida);

static char *sb_writers_name[SB_FREEZE_LEVELS] = {
    "sb_writers",
    "sb_pagefaults",
    "sb_internal",
};

static inline void __super_lock(struct super_block *sb, bool excl)
{
    if (excl)
        down_write(&sb->s_umount);
    else
        down_read(&sb->s_umount);
}

static inline void super_unlock(struct super_block *sb, bool excl)
{
    if (excl)
        up_write(&sb->s_umount);
    else
        up_read(&sb->s_umount);
}

static inline void __super_lock_excl(struct super_block *sb)
{
    __super_lock(sb, true);
}

static inline void super_unlock_excl(struct super_block *sb)
{
    super_unlock(sb, true);
}

/* Free a superblock that has never been seen by anyone */
static void destroy_unused_super(struct super_block *s)
{
    if (!s)
        return;
#if 0
    super_unlock_excl(s);
    list_lru_destroy(&s->s_dentry_lru);
    list_lru_destroy(&s->s_inode_lru);
    shrinker_free(s->s_shrink);
    /* no delays needed */
    destroy_super_work(&s->destroy_work);
#endif
    PANIC("");
}

/**
 * grab_super - acquire an active reference to a superblock
 * @sb: superblock to acquire
 *
 * Acquire a temporary reference on a superblock and try to trade it for
 * an active reference. This is used in sget{_fc}() to wait for a
 * superblock to either become SB_BORN or for it to pass through
 * sb->kill() and be marked as SB_DEAD.
 *
 * Return: This returns true if an active reference could be acquired,
 *         false if not.
 */
static bool grab_super(struct super_block *sb)
{
    bool locked;

#if 0
    sb->s_count++;
    spin_unlock(&sb_lock);
    locked = super_lock_excl(sb);
    if (locked) {
        if (atomic_inc_not_zero(&sb->s_active)) {
            put_super(sb);
            return true;
        }
        super_unlock_excl(sb);
    }
    wait_var_event(&sb->s_flags, super_flags(sb, SB_DEAD));
    put_super(sb);
    return false;
#endif
    PANIC("");
}

/* wake waiters */
#define SUPER_WAKE_FLAGS (SB_BORN | SB_DYING | SB_DEAD)
static void super_wake(struct super_block *sb, unsigned int flag)
{
    WARN_ON_ONCE((flag & ~SUPER_WAKE_FLAGS));
    WARN_ON_ONCE(hweight32(flag & SUPER_WAKE_FLAGS) > 1);

    /*
     * Pairs with smp_load_acquire() in super_lock() to make sure
     * all initializations in the superblock are seen by the user
     * seeing SB_BORN sent.
     */
    smp_store_release(&sb->s_flags, sb->s_flags | flag);
    /*
     * Pairs with the barrier in prepare_to_wait_event() to make sure
     * ___wait_var_event() either sees SB_BORN set or
     * waitqueue_active() check in wake_up_var() sees the waiter.
     */
    smp_mb();
    wake_up_var(&sb->s_flags);
}

/**
 * vfs_get_tree - Get the mountable root
 * @fc: The superblock configuration context.
 *
 * The filesystem is invoked to get or create a superblock which can then later
 * be used for mounting.  The filesystem places a pointer to the root to be
 * used for mounting in @fc->root.
 */
int vfs_get_tree(struct fs_context *fc)
{
    struct super_block *sb;
    int error;

    if (fc->root)
        return -EBUSY;

    /* Get the mountable root in fc->root, with a ref on the root and a ref
     * on the superblock.
     */
    error = fc->ops->get_tree(fc);
    if (error < 0)
        return error;

    if (!fc->root) {
        pr_err("Filesystem %s get_tree() didn't set fc->root, returned %i\n",
               fc->fs_type->name, error);
        /* We don't know what the locking state of the superblock is -
         * if there is a superblock.
         */
        BUG();
    }

    sb = fc->root->d_sb;
    WARN_ON(!sb->s_bdi);

    /*
     * super_wake() contains a memory barrier which also care of
     * ordering for super_cache_count(). We place it before setting
     * SB_BORN as the data dependency between the two functions is
     * the superblock structure contents that we just set up, not
     * the SB_BORN flag.
     */
    super_wake(sb, SB_BORN);

#if 0
    error = security_sb_set_mnt_opts(sb, fc->security, 0, NULL);
    if (unlikely(error)) {
        fc_drop_locked(fc);
        return error;
    }
#endif

    /*
     * filesystems should never set s_maxbytes larger than MAX_LFS_FILESIZE
     * but s_maxbytes was an unsigned long long for many releases. Throw
     * this warning for a little while to try and catch filesystems that
     * violate this rule.
     */
    WARN((sb->s_maxbytes < 0), "%s set sb->s_maxbytes to "
        "negative value (%lld)\n", fc->fs_type->name, sb->s_maxbytes);

    return 0;
}

int set_anon_super_fc(struct super_block *sb, struct fs_context *fc)
{
    return set_anon_super(sb, NULL);
}

int set_anon_super(struct super_block *s, void *data)
{
    return get_anon_bdev(&s->s_dev);
}

/**
 * get_anon_bdev - Allocate a block device for filesystems which don't have one.
 * @p: Pointer to a dev_t.
 *
 * Filesystems which don't use real block devices can call this function
 * to allocate a virtual block device.
 *
 * Context: Any context.  Frequently called while holding sb_lock.
 * Return: 0 on success, -EMFILE if there are no anonymous bdevs left
 * or -ENOMEM if memory allocation failed.
 */
int get_anon_bdev(dev_t *p)
{
    int dev;

    /*
     * Many userspace utilities consider an FSID of 0 invalid.
     * Always return at least 1 from get_anon_bdev.
     */
    dev = ida_alloc_range(&unnamed_dev_ida, 1, (1 << MINORBITS) - 1,
            GFP_ATOMIC);
    if (dev == -ENOSPC)
        dev = -EMFILE;
    if (dev < 0)
        return dev;

    *p = MKDEV(0, dev);
    return 0;
}

static int vfs_get_super(struct fs_context *fc,
        int (*test)(struct super_block *, struct fs_context *),
        int (*fill_super)(struct super_block *sb,
                  struct fs_context *fc))
{
    struct super_block *sb;
    int err;

    sb = sget_fc(fc, test, set_anon_super_fc);
    if (IS_ERR(sb))
        return PTR_ERR(sb);

    if (!sb->s_root) {
        err = fill_super(sb, fc);
        if (err)
            goto error;

        sb->s_flags |= SB_ACTIVE;
    }

    fc->root = dget(sb->s_root);
    return 0;

error:
    deactivate_locked_super(sb);
    return err;
}

int get_tree_nodev(struct fs_context *fc,
          int (*fill_super)(struct super_block *sb,
                    struct fs_context *fc))
{
    return vfs_get_super(fc, NULL, fill_super);
}

/*
 * One thing we have to be careful of with a per-sb shrinker is that we don't
 * drop the last active reference to the superblock from within the shrinker.
 * If that happens we could trigger unregistering the shrinker from within the
 * shrinker path and that leads to deadlock on the shrinker_mutex. Hence we
 * take a passive reference to the superblock to avoid this from occurring.
 */
static unsigned long super_cache_scan(struct shrinker *shrink,
                      struct shrink_control *sc)
{
    PANIC("");
}

static unsigned long super_cache_count(struct shrinker *shrink,
                       struct shrink_control *sc)
{
    PANIC("");
}

/**
 *  alloc_super -   create new superblock
 *  @type:  filesystem type superblock should belong to
 *  @flags: the mount flags
 *  @user_ns: User namespace for the super_block
 *
 *  Allocates and initializes a new &struct super_block.  alloc_super()
 *  returns a pointer new superblock or %NULL if allocation had failed.
 */
static struct super_block *alloc_super(struct file_system_type *type, int flags,
                       struct user_namespace *user_ns)
{
    struct super_block *s = kzalloc(sizeof(struct super_block), GFP_KERNEL);
    static const struct super_operations default_op;
    int i;

    if (!s)
        return NULL;

    printk("%s: step1\n", __func__);
    INIT_LIST_HEAD(&s->s_mounts);
    //s->s_user_ns = get_user_ns(user_ns);
    init_rwsem(&s->s_umount);
    lockdep_set_class(&s->s_umount, &type->s_umount_key);
    /*
     * sget() can have s_umount recursion.
     *
     * When it cannot find a suitable sb, it allocates a new
     * one (this one), and tries again to find a suitable old
     * one.
     *
     * In case that succeeds, it will acquire the s_umount
     * lock of the old one. Since these are clearly distrinct
     * locks, and this object isn't exposed yet, there's no
     * risk of deadlocks.
     *
     * Annotate this by putting this lock in a different
     * subclass.
     */
    down_write_nested(&s->s_umount, SINGLE_DEPTH_NESTING);

#if 0
    if (security_sb_alloc(s))
        goto fail;
#endif

    for (i = 0; i < SB_FREEZE_LEVELS; i++) {
        if (__percpu_init_rwsem(&s->s_writers.rw_sem[i],
                    sb_writers_name[i],
                    &type->s_writers_key[i]))
            goto fail;
    }
    s->s_bdi = &noop_backing_dev_info;
    s->s_flags = flags;
    if (s->s_user_ns != &init_user_ns)
        s->s_iflags |= SB_I_NODEV;
    INIT_HLIST_NODE(&s->s_instances);
    INIT_HLIST_BL_HEAD(&s->s_roots);
    mutex_init(&s->s_sync_lock);
    INIT_LIST_HEAD(&s->s_inodes);
    spin_lock_init(&s->s_inode_list_lock);
    INIT_LIST_HEAD(&s->s_inodes_wb);
    spin_lock_init(&s->s_inode_wblist_lock);

    s->s_count = 1;
    atomic_set(&s->s_active, 1);
    mutex_init(&s->s_vfs_rename_mutex);
    lockdep_set_class(&s->s_vfs_rename_mutex, &type->s_vfs_rename_key);
    init_rwsem(&s->s_dquot.dqio_sem);
    s->s_maxbytes = MAX_NON_LFS;
    s->s_op = &default_op;
    s->s_time_gran = 1000000000;
    s->s_time_min = TIME64_MIN;
    s->s_time_max = TIME64_MAX;

    printk("%s: step2\n", __func__);
    s->s_shrink = shrinker_alloc(SHRINKER_NUMA_AWARE | SHRINKER_MEMCG_AWARE,
                     "sb-%s", type->name);
    if (!s->s_shrink)
        goto fail;

    s->s_shrink->scan_objects = super_cache_scan;
    s->s_shrink->count_objects = super_cache_count;
    s->s_shrink->batch = 1024;
    s->s_shrink->private_data = s;

    if (list_lru_init_memcg(&s->s_dentry_lru, s->s_shrink))
        goto fail;
    if (list_lru_init_memcg(&s->s_inode_lru, s->s_shrink))
        goto fail;

    printk("%s: step3\n", __func__);
    return s;

fail:
    destroy_unused_super(s);
    return NULL;
}

/**
 * sget_fc - Find or create a superblock
 * @fc: Filesystem context.
 * @test: Comparison callback
 * @set: Setup callback
 *
 * Create a new superblock or find an existing one.
 *
 * The @test callback is used to find a matching existing superblock.
 * Whether or not the requested parameters in @fc are taken into account
 * is specific to the @test callback that is used. They may even be
 * completely ignored.
 *
 * If an extant superblock is matched, it will be returned unless:
 *
 * (1) the namespace the filesystem context @fc and the extant
 *     superblock's namespace differ
 *
 * (2) the filesystem context @fc has requested that reusing an extant
 *     superblock is not allowed
 *
 * In both cases EBUSY will be returned.
 *
 * If no match is made, a new superblock will be allocated and basic
 * initialisation will be performed (s_type, s_fs_info and s_id will be
 * set and the @set callback will be invoked), the superblock will be
 * published and it will be returned in a partially constructed state
 * with SB_BORN and SB_ACTIVE as yet unset.
 *
 * Return: On success, an extant or newly created superblock is
 *         returned. On failure an error pointer is returned.
 */
struct super_block *sget_fc(struct fs_context *fc,
                int (*test)(struct super_block *, struct fs_context *),
                int (*set)(struct super_block *, struct fs_context *))
{
    struct super_block *s = NULL;
    struct super_block *old;
    struct user_namespace *user_ns = fc->global ? &init_user_ns : fc->user_ns;
    int err;

    /*
     * Never allow s_user_ns != &init_user_ns when FS_USERNS_MOUNT is
     * not set, as the filesystem is likely unprepared to handle it.
     * This can happen when fsconfig() is called from init_user_ns with
     * an fs_fd opened in another user namespace.
     */
    if (user_ns != &init_user_ns && !(fc->fs_type->fs_flags & FS_USERNS_MOUNT)) {
        errorfc(fc, "VFS: Mounting from non-initial user namespace is not allowed");
        return ERR_PTR(-EPERM);
    }
retry:
    spin_lock(&sb_lock);
    if (test) {
        hlist_for_each_entry(old, &fc->fs_type->fs_supers, s_instances) {
            if (test(old, fc))
                goto share_extant_sb;
        }
    }
    if (!s) {
        spin_unlock(&sb_lock);
        s = alloc_super(fc->fs_type, fc->sb_flags, user_ns);
        if (!s)
            return ERR_PTR(-ENOMEM);
        goto retry;
    }

    s->s_fs_info = fc->s_fs_info;
    err = set(s, fc);
    if (err) {
        s->s_fs_info = NULL;
        spin_unlock(&sb_lock);
        destroy_unused_super(s);
        return ERR_PTR(err);
    }
    fc->s_fs_info = NULL;
    s->s_type = fc->fs_type;
    s->s_iflags |= fc->s_iflags;
    strscpy(s->s_id, s->s_type->name, sizeof(s->s_id));
    /*
     * Make the superblock visible on @super_blocks and @fs_supers.
     * It's in a nascent state and users should wait on SB_BORN or
     * SB_DYING to be set.
     */
    list_add_tail(&s->s_list, &super_blocks);
    hlist_add_head(&s->s_instances, &s->s_type->fs_supers);
    spin_unlock(&sb_lock);
    get_filesystem(s->s_type);
    shrinker_register(s->s_shrink);
    return s;

share_extant_sb:
    if (user_ns != old->s_user_ns || fc->exclusive) {
        spin_unlock(&sb_lock);
        destroy_unused_super(s);
        if (fc->exclusive)
            warnfc(fc, "reusing existing filesystem not allowed");
        else
            warnfc(fc, "reusing existing filesystem in another namespace not allowed");
        return ERR_PTR(-EBUSY);
    }
    if (!grab_super(old))
        goto retry;
    destroy_unused_super(s);
    return old;
}

/**
 *  deactivate_super    -   drop an active reference to superblock
 *  @s: superblock to deactivate
 *
 *  Variant of deactivate_locked_super(), except that superblock is *not*
 *  locked by caller.  If we are going to drop the final active reference,
 *  lock will be acquired prior to that.
 */
void deactivate_super(struct super_block *s)
{
    if (!atomic_add_unless(&s->s_active, -1, 1)) {
        __super_lock_excl(s);
        deactivate_locked_super(s);
    }
}
