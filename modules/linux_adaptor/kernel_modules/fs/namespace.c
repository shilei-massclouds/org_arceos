#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/capability.h>
#include <linux/mnt_namespace.h>
#include <linux/user_namespace.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/idr.h>
#include <linux/init.h>     /* init_rootfs */
#include <linux/fs_struct.h>    /* get_fs_root et.al. */
#include <linux/fsnotify.h> /* fsnotify_vfsmount_delete */
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/proc_ns.h>
#include <linux/magic.h>
#include <linux/memblock.h>
#include <linux/proc_fs.h>
#include <linux/task_work.h>
#include <linux/sched/task.h>
#include <uapi/linux/mount.h>
#include <linux/fs_context.h>
#include <linux/shmem_fs.h>
#include <linux/mnt_idmapping.h>
#include <linux/nospec.h>

#include "pnode.h"
#include "internal.h"

#include "../adaptor.h"

static struct kmem_cache *mnt_cache __ro_after_init;

/* /sys/fs */
struct kobject *fs_kobj __ro_after_init;

static DEFINE_IDA(mnt_id_ida);

/* Don't allow confusion with old 32bit mount ID */
#define MNT_UNIQUE_ID_OFFSET (1ULL << 31)
static atomic64_t mnt_id_ctr = ATOMIC64_INIT(MNT_UNIQUE_ID_OFFSET);

/*
 * vfsmount lock may be taken for read to prevent changes to the
 * vfsmount hash, ie. during mountpoint lookups or walking back
 * up the tree.
 *
 * It should be taken for write in all cases where the vfsmount
 * tree or hash is modified or when a vfsmount structure is modified.
 */
__cacheline_aligned_in_smp DEFINE_SEQLOCK(mount_lock);

struct vfsmount *kern_mount(struct file_system_type *type)
{
    struct vfsmount *mnt;
    mnt = vfs_kern_mount(type, SB_KERNMOUNT, type->name, NULL);
    if (!IS_ERR(mnt)) {
        /*
         * it is a longterm mount, don't release mnt until
         * we unmount before file sys is unregistered
        */
        real_mount(mnt)->mnt_ns = MNT_NS_INTERNAL;
    }
    return mnt;
}

struct vfsmount *vfs_kern_mount(struct file_system_type *type,
                int flags, const char *name,
                void *data)
{
    struct fs_context *fc;
    struct vfsmount *mnt;
    int ret = 0;

    if (!type)
        return ERR_PTR(-EINVAL);

    fc = fs_context_for_mount(type, flags);
    if (IS_ERR(fc))
        return ERR_CAST(fc);

    if (name)
        ret = vfs_parse_fs_string(fc, "source",
                      name, strlen(name));
    if (!ret)
        ret = parse_monolithic_mount_data(fc, data);
    if (!ret)
        mnt = fc_mount(fc);
    else
        mnt = ERR_PTR(ret);

    printk("%s: name: %s, ret: %d\n", __func__, name, ret);
    put_fs_context(fc);
    printk("%s: ok\n", __func__);
    return mnt;
}

/*
 * Most r/o checks on a fs are for operations that take
 * discrete amounts of time, like a write() or unlink().
 * We must keep track of when those operations start
 * (for permission checks) and when they end, so that
 * we can determine when writes are able to occur to
 * a filesystem.
 */
/*
 * __mnt_is_readonly: check whether a mount is read-only
 * @mnt: the mount to check for its write status
 *
 * This shouldn't be used directly ouside of the VFS.
 * It does not guarantee that the filesystem will stay
 * r/w, just that it is right *now*.  This can not and
 * should not be used in place of IS_RDONLY(inode).
 * mnt_want/drop_write() will _keep_ the filesystem
 * r/w.
 */
bool __mnt_is_readonly(struct vfsmount *mnt)
{
    return (mnt->mnt_flags & MNT_READONLY) || sb_rdonly(mnt->mnt_sb);
}

static int mnt_is_readonly(struct vfsmount *mnt)
{
    if (READ_ONCE(mnt->mnt_sb->s_readonly_remount))
        return 1;
    /*
     * The barrier pairs with the barrier in sb_start_ro_state_change()
     * making sure if we don't see s_readonly_remount set yet, we also will
     * not see any superblock / mount flag changes done by remount.
     * It also pairs with the barrier in sb_end_ro_state_change()
     * assuring that if we see s_readonly_remount already cleared, we will
     * see the values of superblock / mount flags updated by remount.
     */
    smp_rmb();
    return __mnt_is_readonly(mnt);
}

static inline void mnt_inc_writers(struct mount *mnt)
{
#ifdef CONFIG_SMP
    this_cpu_inc(mnt->mnt_pcp->mnt_writers);
#else
    mnt->mnt_writers++;
#endif
}

static inline void mnt_dec_writers(struct mount *mnt)
{
#ifdef CONFIG_SMP
    this_cpu_dec(mnt->mnt_pcp->mnt_writers);
#else
    mnt->mnt_writers--;
#endif
}

struct vfsmount *fc_mount(struct fs_context *fc)
{
    int err = vfs_get_tree(fc);
    if (!err) {
        up_write(&fc->root->d_sb->s_umount);
        return vfs_create_mount(fc);
    }
    return ERR_PTR(err);
}

static int mnt_alloc_id(struct mount *mnt)
{
    int res = ida_alloc(&mnt_id_ida, GFP_KERNEL);

    if (res < 0)
        return res;
    mnt->mnt_id = res;
    mnt->mnt_id_unique = atomic64_inc_return(&mnt_id_ctr);
    return 0;
}

static void mnt_free_id(struct mount *mnt)
{
    ida_free(&mnt_id_ida, mnt->mnt_id);
}

static struct mount *alloc_vfsmnt(const char *name)
{
    struct mount *mnt = kmem_cache_zalloc(mnt_cache, GFP_KERNEL);
    if (mnt) {
        int err;

        err = mnt_alloc_id(mnt);
        if (err)
            goto out_free_cache;

        if (name) {
            mnt->mnt_devname = kstrdup_const(name,
                             GFP_KERNEL_ACCOUNT);
            if (!mnt->mnt_devname)
                goto out_free_id;
        }

#ifdef CONFIG_SMP
        mnt->mnt_pcp = alloc_percpu(struct mnt_pcp);
        if (!mnt->mnt_pcp)
            goto out_free_devname;

        this_cpu_add(mnt->mnt_pcp->mnt_count, 1);
#else
        mnt->mnt_count = 1;
        mnt->mnt_writers = 0;
#endif

        INIT_HLIST_NODE(&mnt->mnt_hash);
        INIT_LIST_HEAD(&mnt->mnt_child);
        INIT_LIST_HEAD(&mnt->mnt_mounts);
        INIT_LIST_HEAD(&mnt->mnt_list);
        INIT_LIST_HEAD(&mnt->mnt_expire);
        INIT_LIST_HEAD(&mnt->mnt_share);
        INIT_LIST_HEAD(&mnt->mnt_slave_list);
        INIT_LIST_HEAD(&mnt->mnt_slave);
        INIT_HLIST_NODE(&mnt->mnt_mp_list);
        INIT_LIST_HEAD(&mnt->mnt_umounting);
        INIT_HLIST_HEAD(&mnt->mnt_stuck_children);
        RB_CLEAR_NODE(&mnt->mnt_node);
        mnt->mnt.mnt_idmap = &nop_mnt_idmap;
    }
    return mnt;

#ifdef CONFIG_SMP
out_free_devname:
    kfree_const(mnt->mnt_devname);
#endif
out_free_id:
    mnt_free_id(mnt);
out_free_cache:
    kmem_cache_free(mnt_cache, mnt);
    return NULL;
}

static inline void lock_mount_hash(void)
{
    write_seqlock(&mount_lock);
}

static inline void unlock_mount_hash(void)
{
    write_sequnlock(&mount_lock);
}

/*
 * vfsmount lock must be held for read
 */
static inline void mnt_add_count(struct mount *mnt, int n)
{
#ifdef CONFIG_SMP
    this_cpu_add(mnt->mnt_pcp->mnt_count, n);
#else
    preempt_disable();
    mnt->mnt_count += n;
    preempt_enable();
#endif
}

static void cleanup_mnt(struct mount *mnt)
{
#if 0
    struct hlist_node *p;
    struct mount *m;
    /*
     * The warning here probably indicates that somebody messed
     * up a mnt_want/drop_write() pair.  If this happens, the
     * filesystem was probably unable to make r/w->r/o transitions.
     * The locking used to deal with mnt_count decrement provides barriers,
     * so mnt_get_writers() below is safe.
     */
    WARN_ON(mnt_get_writers(mnt));
    if (unlikely(mnt->mnt_pins.first))
        mnt_pin_kill(mnt);
    hlist_for_each_entry_safe(m, p, &mnt->mnt_stuck_children, mnt_umount) {
        hlist_del(&m->mnt_umount);
        mntput(&m->mnt);
    }
    fsnotify_vfsmount_delete(&mnt->mnt);
    dput(mnt->mnt.mnt_root);
    deactivate_super(mnt->mnt.mnt_sb);
    mnt_free_id(mnt);
    call_rcu(&mnt->mnt_rcu, delayed_free_vfsmnt);
#endif
    PANIC("");
}

static LLIST_HEAD(delayed_mntput_list);
static void delayed_mntput(struct work_struct *unused)
{
    struct llist_node *node = llist_del_all(&delayed_mntput_list);
    struct mount *m, *t;

    llist_for_each_entry_safe(m, t, node, mnt_llist)
        cleanup_mnt(m);
}
static DECLARE_DELAYED_WORK(delayed_mntput_work, delayed_mntput);

static void __cleanup_mnt(struct rcu_head *head)
{
    cleanup_mnt(container_of(head, struct mount, mnt_rcu));
}

static void mntput_no_expire(struct mount *mnt)
{
    LIST_HEAD(list);
    int count;

    rcu_read_lock();
    if (likely(READ_ONCE(mnt->mnt_ns))) {
        /*
         * Since we don't do lock_mount_hash() here,
         * ->mnt_ns can change under us.  However, if it's
         * non-NULL, then there's a reference that won't
         * be dropped until after an RCU delay done after
         * turning ->mnt_ns NULL.  So if we observe it
         * non-NULL under rcu_read_lock(), the reference
         * we are dropping is not the final one.
         */
        mnt_add_count(mnt, -1);
        rcu_read_unlock();
        return;
    }
    lock_mount_hash();
    /*
     * make sure that if __legitimize_mnt() has not seen us grab
     * mount_lock, we'll see their refcount increment here.
     */
    smp_mb();
    mnt_add_count(mnt, -1);
    count = mnt_get_count(mnt);
    if (count != 0) {
        WARN_ON(count < 0);
        rcu_read_unlock();
        unlock_mount_hash();
        return;
    }
    if (unlikely(mnt->mnt.mnt_flags & MNT_DOOMED)) {
        rcu_read_unlock();
        unlock_mount_hash();
        return;
    }
    mnt->mnt.mnt_flags |= MNT_DOOMED;
    rcu_read_unlock();

    list_del(&mnt->mnt_instance);

    if (unlikely(!list_empty(&mnt->mnt_mounts))) {
#if 0
        struct mount *p, *tmp;
        list_for_each_entry_safe(p, tmp, &mnt->mnt_mounts,  mnt_child) {
            __put_mountpoint(unhash_mnt(p), &list);
            hlist_add_head(&p->mnt_umount, &mnt->mnt_stuck_children);
        }
#endif
        PANIC("");
    }
    unlock_mount_hash();
    shrink_dentry_list(&list);

    if (likely(!(mnt->mnt.mnt_flags & MNT_INTERNAL))) {
        struct task_struct *task = current;
        if (likely(!(task->flags & PF_KTHREAD))) {
            init_task_work(&mnt->mnt_rcu, __cleanup_mnt);
            if (!task_work_add(task, &mnt->mnt_rcu, TWA_RESUME))
                return;
        }
        if (llist_add(&mnt->mnt_llist, &delayed_mntput_list))
            schedule_delayed_work(&delayed_mntput_work, 1);
        return;
    }
#if 0
    cleanup_mnt(mnt);
#endif

    PANIC("");
}

/*
 * vfsmount lock must be held for write
 */
int mnt_get_count(struct mount *mnt)
{
#ifdef CONFIG_SMP
    int count = 0;
    int cpu;

    for_each_possible_cpu(cpu) {
        count += per_cpu_ptr(mnt->mnt_pcp, cpu)->mnt_count;
    }

    return count;
#else
    return mnt->mnt_count;
#endif
}

struct vfsmount *mntget(struct vfsmount *mnt)
{
    if (mnt)
        mnt_add_count(real_mount(mnt), 1);
    return mnt;
}

void mntput(struct vfsmount *mnt)
{
    if (mnt) {
        struct mount *m = real_mount(mnt);
        /* avoid cacheline pingpong */
        if (unlikely(m->mnt_expiry_mark))
            WRITE_ONCE(m->mnt_expiry_mark, 0);
        mntput_no_expire(m);
    }
}

/**
 * vfs_create_mount - Create a mount for a configured superblock
 * @fc: The configuration context with the superblock attached
 *
 * Create a mount to an already configured superblock.  If necessary, the
 * caller should invoke vfs_get_tree() before calling this.
 *
 * Note that this does not attach the mount to anything.
 */
struct vfsmount *vfs_create_mount(struct fs_context *fc)
{
    struct mount *mnt;

    if (!fc->root)
        return ERR_PTR(-EINVAL);

    mnt = alloc_vfsmnt(fc->source ?: "none");
    if (!mnt)
        return ERR_PTR(-ENOMEM);

    if (fc->sb_flags & SB_KERNMOUNT)
        mnt->mnt.mnt_flags = MNT_INTERNAL;

    atomic_inc(&fc->root->d_sb->s_active);
    mnt->mnt.mnt_sb     = fc->root->d_sb;
    mnt->mnt.mnt_root   = dget(fc->root);
    mnt->mnt_mountpoint = mnt->mnt.mnt_root;
    mnt->mnt_parent     = mnt;

    lock_mount_hash();
    list_add_tail(&mnt->mnt_instance, &mnt->mnt.mnt_sb->s_mounts);
    unlock_mount_hash();
    return &mnt->mnt;
}

/* call under rcu_read_lock */
int __legitimize_mnt(struct vfsmount *bastard, unsigned seq)
{
    struct mount *mnt;
    if (read_seqretry(&mount_lock, seq))
        return 1;
    if (bastard == NULL)
        return 0;
    mnt = real_mount(bastard);
    mnt_add_count(mnt, 1);
    smp_mb();       // see mntput_no_expire() and do_umount()
    if (likely(!read_seqretry(&mount_lock, seq)))
        return 0;
    lock_mount_hash();
    if (unlikely(bastard->mnt_flags & (MNT_SYNC_UMOUNT | MNT_DOOMED))) {
        mnt_add_count(mnt, -1);
        unlock_mount_hash();
        return 1;
    }
    unlock_mount_hash();
    /* caller will mntput() */
    return -1;
}

bool path_is_under(const struct path *path1, const struct path *path2)
{
    PANIC("");
}

/**
 * mnt_want_write - get write access to a mount
 * @m: the mount on which to take a write
 *
 * This tells the low-level filesystem that a write is about to be performed to
 * it, and makes sure that writes are allowed (mount is read-write, filesystem
 * is not frozen) before returning success.  When the write operation is
 * finished, mnt_drop_write() must be called.  This is effectively a refcount.
 */
int mnt_want_write(struct vfsmount *m)
{
    int ret;

    sb_start_write(m->mnt_sb);
    ret = mnt_get_write_access(m);
    if (ret)
        sb_end_write(m->mnt_sb);
    return ret;
}

/*
 * Most r/o & frozen checks on a fs are for operations that take discrete
 * amounts of time, like a write() or unlink().  We must keep track of when
 * those operations start (for permission checks) and when they end, so that we
 * can determine when writes are able to occur to a filesystem.
 */
/**
 * mnt_get_write_access - get write access to a mount without freeze protection
 * @m: the mount on which to take a write
 *
 * This tells the low-level filesystem that a write is about to be performed to
 * it, and makes sure that writes are allowed (mnt it read-write) before
 * returning success. This operation does not protect against filesystem being
 * frozen. When the write operation is finished, mnt_put_write_access() must be
 * called. This is effectively a refcount.
 */
int mnt_get_write_access(struct vfsmount *m)
{
    struct mount *mnt = real_mount(m);
    int ret = 0;

    preempt_disable();
    mnt_inc_writers(mnt);
    /*
     * The store to mnt_inc_writers must be visible before we pass
     * MNT_WRITE_HOLD loop below, so that the slowpath can see our
     * incremented count after it has set MNT_WRITE_HOLD.
     */
    smp_mb();
    might_lock(&mount_lock.lock);
    while (READ_ONCE(mnt->mnt.mnt_flags) & MNT_WRITE_HOLD) {
        if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
            cpu_relax();
        } else {
            /*
             * This prevents priority inversion, if the task
             * setting MNT_WRITE_HOLD got preempted on a remote
             * CPU, and it prevents life lock if the task setting
             * MNT_WRITE_HOLD has a lower priority and is bound to
             * the same CPU as the task that is spinning here.
             */
            preempt_enable();
            lock_mount_hash();
            unlock_mount_hash();
            preempt_disable();
        }
    }
    /*
     * The barrier pairs with the barrier sb_start_ro_state_change() making
     * sure that if we see MNT_WRITE_HOLD cleared, we will also see
     * s_readonly_remount set (or even SB_RDONLY / MNT_READONLY flags) in
     * mnt_is_readonly() and bail in case we are racing with remount
     * read-only.
     */
    smp_rmb();
    if (mnt_is_readonly(m)) {
        mnt_dec_writers(mnt);
        ret = -EROFS;
    }
    preempt_enable();
    return ret;
}

/**
 * mnt_put_write_access - give up write access to a mount
 * @mnt: the mount on which to give up write access
 *
 * Tells the low-level filesystem that we are done
 * performing writes to it.  Must be matched with
 * mnt_get_write_access() call above.
 */
void mnt_put_write_access(struct vfsmount *mnt)
{
    preempt_disable();
    mnt_dec_writers(real_mount(mnt));
    preempt_enable();
}

/**
 * mnt_drop_write - give up write access to a mount
 * @mnt: the mount on which to give up write access
 *
 * Tells the low-level filesystem that we are done performing writes to it and
 * also allows filesystem to be frozen again.  Must be matched with
 * mnt_want_write() call above.
 */
void mnt_drop_write(struct vfsmount *mnt)
{
    mnt_put_write_access(mnt);
    sb_end_write(mnt->mnt_sb);
}

void dissolve_on_fput(struct vfsmount *mnt)
{
    PANIC("");
}

/*
 * __is_local_mountpoint - Test to see if dentry is a mountpoint in the
 *                         current mount namespace.
 *
 * The common case is dentries are not mountpoints at all and that
 * test is handled inline.  For the slow case when we are actually
 * dealing with a mountpoint of some kind, walk through all of the
 * mounts in the current mount namespace and test to see if the dentry
 * is a mountpoint.
 *
 * The mount_hashtable is not usable in the context because we
 * need to identify all mounts that may be in the current mount
 * namespace not just a mount that happens to have some specified
 * parent mount.
 */
bool __is_local_mountpoint(struct dentry *dentry)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

void __init mnt_init(void)
{
    int err;

    mnt_cache = kmem_cache_create("mnt_cache", sizeof(struct mount),
            0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);

    pr_err("%s: No impl.", __func__);
#if 0
    mount_hashtable = alloc_large_system_hash("Mount-cache",
                sizeof(struct hlist_head),
                mhash_entries, 19,
                HASH_ZERO,
                &m_hash_shift, &m_hash_mask, 0, 0);
    mountpoint_hashtable = alloc_large_system_hash("Mountpoint-cache",
                sizeof(struct hlist_head),
                mphash_entries, 19,
                HASH_ZERO,
                &mp_hash_shift, &mp_hash_mask, 0, 0);

    if (!mount_hashtable || !mountpoint_hashtable)
        panic("Failed to allocate mount hash table\n");

    kernfs_init();

    err = sysfs_init();
    if (err)
        printk(KERN_WARNING "%s: sysfs_init error: %d\n",
            __func__, err);
#endif
    fs_kobj = kobject_create_and_add("fs", NULL);
    if (!fs_kobj)
        printk(KERN_WARNING "%s: kobj create error\n", __func__);
#if 0
    shmem_init();
    init_rootfs();
    init_mount_tree();
#endif
}
