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

struct vfsmount *mntget(struct vfsmount *mnt)
{
    if (mnt)
        mnt_add_count(real_mount(mnt), 1);
    return mnt;
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
