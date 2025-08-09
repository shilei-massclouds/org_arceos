#include <linux/init.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/wordpart.h>
#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/sched/mm.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/device_cgroup.h>
#include <linux/fs_struct.h>
#include <linux/posix_acl.h>
#include <linux/hash.h>
#include <linux/bitops.h>
#include <linux/init_task.h>
#include <linux/uaccess.h>

#include "internal.h"
#include "mount.h"
#include "../adaptor.h"

#define EMBEDDED_LEVELS 2
struct nameidata {
    struct path path;
    struct qstr last;
    struct path root;
    struct inode    *inode; /* path.dentry.d_inode */
    unsigned int    flags, state;
    unsigned    seq, next_seq, m_seq, r_seq;
    int     last_type;
    unsigned    depth;
    int     total_link_count;
    struct saved {
        struct path link;
        struct delayed_call done;
        const char *name;
        unsigned seq;
    } *stack, internal[EMBEDDED_LEVELS];
    struct filename *name;
    struct nameidata *saved;
    unsigned    root_seq;
    int     dfd;
    vfsuid_t    dir_vfsuid;
    umode_t     dir_mode;
} __randomize_layout;

#define EMBEDDED_NAME_MAX   (PATH_MAX - offsetof(struct filename, iname))

struct filename *
getname_flags(const char __user *filename, int flags)
{
    struct filename *result;
    char *kname;
    int len;

    result = audit_reusename(filename);
    if (result)
        return result;

    result = __getname();
    if (unlikely(!result))
        return ERR_PTR(-ENOMEM);

    /*
     * First, try to embed the struct filename inside the names_cache
     * allocation
     */
    kname = (char *)result->iname;
    result->name = kname;

    len = strncpy_from_user(kname, filename, EMBEDDED_NAME_MAX);
    /*
     * Handle both empty path and copy failure in one go.
     */
    if (unlikely(len <= 0)) {
        if (unlikely(len < 0)) {
            __putname(result);
            return ERR_PTR(len);
        }

        /* The empty path is special. */
        if (!(flags & LOOKUP_EMPTY)) {
            __putname(result);
            return ERR_PTR(-ENOENT);
        }
    }

    /*
     * Uh-oh. We have a name that's approaching PATH_MAX. Allocate a
     * separate struct filename so we can dedicate the entire
     * names_cache allocation for the pathname, and re-do the copy from
     * userland.
     */
    if (unlikely(len == EMBEDDED_NAME_MAX)) {
        PANIC("approach EMBEDDED_NAME_MAX");
    }

    atomic_set(&result->refcnt, 1);
    result->uptr = filename;
    result->aname = NULL;
    return result;
}

struct filename *
getname(const char __user * filename)
{
    return getname_flags(filename, 0);
}

void putname(struct filename *name)
{
    if (IS_ERR(name))
        return;

    if (WARN_ON_ONCE(!atomic_read(&name->refcnt)))
        return;

    if (!atomic_dec_and_test(&name->refcnt))
        return;

    if (name->name != name->iname) {
        __putname(name->name);
        kfree(name);
    } else
        __putname(name);
}

static void drop_links(struct nameidata *nd)
{
    int i = nd->depth;
    while (i--) {
        struct saved *last = nd->stack + i;
        do_delayed_call(&last->done);
        clear_delayed_call(&last->done);
    }
}

#define ND_ROOT_PRESET 1
#define ND_ROOT_GRABBED 2
#define ND_JUMPED 4

static void leave_rcu(struct nameidata *nd)
{
    nd->flags &= ~LOOKUP_RCU;
    nd->seq = nd->next_seq = 0;
    rcu_read_unlock();
}

static void terminate_walk(struct nameidata *nd)
{
    drop_links(nd);
    if (!(nd->flags & LOOKUP_RCU)) {
        int i;
        path_put(&nd->path);
        for (i = 0; i < nd->depth; i++)
            path_put(&nd->stack[i].link);
        if (nd->state & ND_ROOT_GRABBED) {
            path_put(&nd->root);
            nd->state &= ~ND_ROOT_GRABBED;
        }
    } else {
        leave_rcu(nd);
    }
    nd->depth = 0;
    nd->path.mnt = NULL;
    nd->path.dentry = NULL;
}

static int handle_truncate(struct mnt_idmap *idmap, struct file *filp)
{
    PANIC("");
}

static void __set_nameidata(struct nameidata *p, int dfd, struct filename *name)
{
    struct nameidata *old = current->nameidata;
    p->stack = p->internal;
    p->depth = 0;
    p->dfd = dfd;
    p->name = name;
    p->path.mnt = NULL;
    p->path.dentry = NULL;
    p->total_link_count = old ? old->total_link_count : 0;
    p->saved = old;
    current->nameidata = p;
}

static inline void set_nameidata(struct nameidata *p, int dfd, struct filename *name,
              const struct path *root)
{
    __set_nameidata(p, dfd, name);
    p->state = 0;
    if (unlikely(root)) {
        p->state = ND_ROOT_PRESET;
        p->root = *root;
    }
}

static void restore_nameidata(void)
{
    struct nameidata *now = current->nameidata, *old = now->saved;

    current->nameidata = old;
    if (old)
        old->total_link_count = now->total_link_count;
    if (now->stack != now->internal)
        kfree(now->stack);
}

static int do_tmpfile(struct nameidata *nd, unsigned flags,
        const struct open_flags *op,
        struct file *file)
{
    PANIC("");
}

static int do_o_path(struct nameidata *nd, unsigned flags, struct file *file)
{
    PANIC("");
}

static int set_root(struct nameidata *nd)
{
    struct fs_struct *fs = current->fs;

    /*
     * Jumping to the real root in a scoped-lookup is a BUG in namei, but we
     * still have to ensure it doesn't happen because it will cause a breakout
     * from the dirfd.
     */
    if (WARN_ON(nd->flags & LOOKUP_IS_SCOPED))
        return -ENOTRECOVERABLE;

    if (nd->flags & LOOKUP_RCU) {
        unsigned seq;

        do {
            seq = read_seqcount_begin(&fs->seq);
            nd->root = fs->root;
            nd->root_seq = __read_seqcount_begin(&nd->root.dentry->d_seq);
        } while (read_seqcount_retry(&fs->seq, seq));
    } else {
        get_fs_root(fs, &nd->root);
        nd->state |= ND_ROOT_GRABBED;
    }
    return 0;
}

static int nd_jump_root(struct nameidata *nd)
{
    if (unlikely(nd->flags & LOOKUP_BENEATH))
        return -EXDEV;
    if (unlikely(nd->flags & LOOKUP_NO_XDEV)) {
        /* Absolute path arguments to path_init() are allowed. */
        if (nd->path.mnt != NULL && nd->path.mnt != nd->root.mnt)
            return -EXDEV;
    }
    if (!nd->root.mnt) {
        int error = set_root(nd);
        if (error)
            return error;
    }
    if (nd->flags & LOOKUP_RCU) {
        struct dentry *d;
        nd->path = nd->root;
        d = nd->path.dentry;
        nd->inode = d->d_inode;
        nd->seq = nd->root_seq;
        if (read_seqcount_retry(&d->d_seq, nd->seq))
            return -ECHILD;
    } else {
        path_put(&nd->path);
        nd->path = nd->root;
        path_get(&nd->path);
        nd->inode = nd->path.dentry->d_inode;
    }
    nd->state |= ND_JUMPED;
    return 0;
}

/**
 * path_get - get a reference to a path
 * @path: path to get the reference to
 *
 * Given a path increment the reference count to the dentry and the vfsmount.
 */
void path_get(const struct path *path)
{
    mntget(path->mnt);
    dget(path->dentry);
}

/**
 * path_put - put a reference to a path
 * @path: path to put the reference to
 *
 * Given a path decrement the reference count to the dentry and the vfsmount.
 */
void path_put(const struct path *path)
{
    dput(path->dentry);
    mntput(path->mnt);
}

/* must be paired with terminate_walk() */
static const char *path_init(struct nameidata *nd, unsigned flags)
{
    int error;
    const char *s = nd->name->name;

    /* LOOKUP_CACHED requires RCU, ask caller to retry */
    if ((flags & (LOOKUP_RCU | LOOKUP_CACHED)) == LOOKUP_CACHED)
        return ERR_PTR(-EAGAIN);

    if (!*s)
        flags &= ~LOOKUP_RCU;
    if (flags & LOOKUP_RCU)
        rcu_read_lock();
    else
        nd->seq = nd->next_seq = 0;

    nd->flags = flags;
    nd->state |= ND_JUMPED;

    nd->m_seq = __read_seqcount_begin(&mount_lock.seqcount);
    nd->r_seq = __read_seqcount_begin(&rename_lock.seqcount);
    smp_rmb();

    if (nd->state & ND_ROOT_PRESET) {
        PANIC("ND_ROOT_PRESET");
    }

    nd->root.mnt = NULL;

    /* Absolute pathname -- fetch the root (LOOKUP_IN_ROOT uses nd->dfd). */
    if (*s == '/' && !(flags & LOOKUP_IN_ROOT)) {
        error = nd_jump_root(nd);
        if (unlikely(error))
            return ERR_PTR(error);
        return s;
    }


    PANIC("");
}

/*
 * Name resolution.
 * This is the basic name resolution function, turning a pathname into
 * the final dentry. We expect 'base' to be positive and a directory.
 *
 * Returns 0 and nd will have valid dentry and mnt on success.
 * Returns error and drops reference to input namei data on failure.
 */
static int link_path_walk(const char *name, struct nameidata *nd)
{
    int depth = 0; // depth <= nd->depth
    int err;

    nd->last_type = LAST_ROOT;
    nd->flags |= LOOKUP_PARENT;
    if (IS_ERR(name))
        return PTR_ERR(name);
    while (*name=='/')
        name++;
    if (!*name) {
        nd->dir_mode = 0; // short-circuit the 'hardening' idiocy
        return 0;
    }

    /* At this point we know we have a real path component. */
    for(;;) {
        PANIC("LOOP");
    }
}

static inline void put_link(struct nameidata *nd)
{
    struct saved *last = nd->stack + --nd->depth;
    do_delayed_call(&last->done);
    if (!(nd->flags & LOOKUP_RCU))
        path_put(&last->link);
}

static const char *handle_dots(struct nameidata *nd, int type)
{
    if (type == LAST_DOTDOT) {
        PANIC("LAST_DOTDOT");
    }
    return NULL;
}

static const char *open_last_lookups(struct nameidata *nd,
           struct file *file, const struct open_flags *op)
{
    struct dentry *dir = nd->path.dentry;
    int open_flag = op->open_flag;
    bool got_write = false;
    struct dentry *dentry;
    const char *res;

    nd->flags |= op->intent;

    if (nd->last_type != LAST_NORM) {
        if (nd->depth)
            put_link(nd);
        return handle_dots(nd, nd->last_type);
    }

    printk("%s: step1\n", __func__);
#if 0
    /* We _can_ be in RCU mode here */
    dentry = lookup_fast_for_open(nd, open_flag);
    if (IS_ERR(dentry))
        return ERR_CAST(dentry);
#endif

    PANIC("");
}

/* path_put is needed afterwards regardless of success or failure */
static bool __legitimize_path(struct path *path, unsigned seq, unsigned mseq)
{
    int res = __legitimize_mnt(path->mnt, mseq);
    if (unlikely(res)) {
        if (res > 0)
            path->mnt = NULL;
        path->dentry = NULL;
        return false;
    }
    if (unlikely(!lockref_get_not_dead(&path->dentry->d_lockref))) {
        path->dentry = NULL;
        return false;
    }
    return !read_seqcount_retry(&path->dentry->d_seq, seq);
}

static inline bool legitimize_path(struct nameidata *nd,
                struct path *path, unsigned seq)
{
    return __legitimize_path(path, seq, nd->m_seq);
}

static bool legitimize_links(struct nameidata *nd)
{
    int i;
    if (unlikely(nd->flags & LOOKUP_CACHED)) {
        drop_links(nd);
        nd->depth = 0;
        return false;
    }
    for (i = 0; i < nd->depth; i++) {
        struct saved *last = nd->stack + i;
        if (unlikely(!legitimize_path(nd, &last->link, last->seq))) {
            drop_links(nd);
            nd->depth = i + 1;
            return false;
        }
    }
    return true;
}

static bool legitimize_root(struct nameidata *nd)
{
    /* Nothing to do if nd->root is zero or is managed by the VFS user. */
    if (!nd->root.mnt || (nd->state & ND_ROOT_PRESET))
        return true;
    nd->state |= ND_ROOT_GRABBED;
    return legitimize_path(nd, &nd->root, nd->root_seq);
}

/**
 * try_to_unlazy - try to switch to ref-walk mode.
 * @nd: nameidata pathwalk data
 * Returns: true on success, false on failure
 *
 * try_to_unlazy attempts to legitimize the current nd->path and nd->root
 * for ref-walk mode.
 * Must be called from rcu-walk context.
 * Nothing should touch nameidata between try_to_unlazy() failure and
 * terminate_walk().
 */
static bool try_to_unlazy(struct nameidata *nd)
{
    struct dentry *parent = nd->path.dentry;

    BUG_ON(!(nd->flags & LOOKUP_RCU));

    if (unlikely(!legitimize_links(nd)))
        goto out1;
    if (unlikely(!legitimize_path(nd, &nd->path, nd->seq)))
        goto out;
    if (unlikely(!legitimize_root(nd)))
        goto out;
    leave_rcu(nd);
    BUG_ON(nd->inode != parent->d_inode);
    return true;

out1:
    nd->path.mnt = NULL;
    nd->path.dentry = NULL;
out:
    leave_rcu(nd);
    PANIC("ERR");
    return false;
}

/**
 * complete_walk - successful completion of path walk
 * @nd:  pointer nameidata
 *
 * If we had been in RCU mode, drop out of it and legitimize nd->path.
 * Revalidate the final result, unless we'd already done that during
 * the path walk or the filesystem doesn't ask for it.  Return 0 on
 * success, -error on failure.  In case of failure caller does not
 * need to drop nd->path.
 */
static int complete_walk(struct nameidata *nd)
{
    struct dentry *dentry = nd->path.dentry;
    int status;

    if (nd->flags & LOOKUP_RCU) {
        /*
         * We don't want to zero nd->root for scoped-lookups or
         * externally-managed nd->root.
         */
        if (!(nd->state & ND_ROOT_PRESET))
            if (!(nd->flags & LOOKUP_IS_SCOPED))
                nd->root.mnt = NULL;
        nd->flags &= ~LOOKUP_CACHED;
        if (!try_to_unlazy(nd))
            return -ECHILD;
    }

    if (unlikely(nd->flags & LOOKUP_IS_SCOPED)) {
        /*
         * While the guarantee of LOOKUP_IS_SCOPED is (roughly) "don't
         * ever step outside the root during lookup" and should already
         * be guaranteed by the rest of namei, we want to avoid a namei
         * BUG resulting in userspace being given a path that was not
         * scoped within the root at some point during the lookup.
         *
         * So, do a final sanity-check to make sure that in the
         * worst-case scenario (a complete bypass of LOOKUP_IS_SCOPED)
         * we won't silently return an fd completely outside of the
         * requested root to userspace.
         *
         * Userspace could move the path outside the root after this
         * check, but as discussed elsewhere this is not a concern (the
         * resolved file was inside the root at some point).
         */
        if (!path_is_under(&nd->path, &nd->root))
            return -EXDEV;
    }

    if (likely(!(nd->state & ND_JUMPED)))
        return 0;

    if (likely(!(dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE)))
        return 0;

#if 0
    status = dentry->d_op->d_weak_revalidate(dentry, nd->flags);
    if (status > 0)
        return 0;

    if (!status)
        status = -ESTALE;
#endif

    PANIC("");
    return status;
}

/**
 * may_create_in_sticky - Check whether an O_CREAT open in a sticky directory
 *            should be allowed, or not, on files that already
 *            exist.
 * @idmap: idmap of the mount the inode was found from
 * @nd: nameidata pathwalk data
 * @inode: the inode of the file to open
 *
 * Block an O_CREAT open of a FIFO (or a regular file) when:
 *   - sysctl_protected_fifos (or sysctl_protected_regular) is enabled
 *   - the file already exists
 *   - we are in a sticky directory
 *   - we don't own the file
 *   - the owner of the directory doesn't own the file
 *   - the directory is world writable
 * If the sysctl_protected_fifos (or sysctl_protected_regular) is set to 2
 * the directory doesn't have to be world writable: being group writable will
 * be enough.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply pass @nop_mnt_idmap.
 *
 * Returns 0 if the open is allowed, -ve on error.
 */
static int may_create_in_sticky(struct mnt_idmap *idmap, struct nameidata *nd,
                struct inode *const inode)
{
    PANIC("");
}

bool may_open_dev(const struct path *path)
{
    return !(path->mnt->mnt_flags & MNT_NODEV) &&
        !(path->mnt->mnt_sb->s_iflags & SB_I_NODEV);
}

/**
 * sb_permission - Check superblock-level permissions
 * @sb: Superblock of inode to check permission on
 * @inode: Inode to check permission on
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Separate out file-system wide checks from inode-specific permission checks.
 */
static int sb_permission(struct super_block *sb, struct inode *inode, int mask)
{
    if (unlikely(mask & MAY_WRITE)) {
        umode_t mode = inode->i_mode;

        /* Nobody gets write access to a read-only fs. */
        if (sb_rdonly(sb) && (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
            return -EROFS;
    }
    return 0;
}

/**
 * generic_permission -  check for access rights on a Posix-like filesystem
 * @idmap:  idmap of the mount the inode was found from
 * @inode:  inode to check access rights for
 * @mask:   right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC,
 *      %MAY_NOT_BLOCK ...)
 *
 * Used to check for read/write/execute permissions on a file.
 * We use "fsuid" for this, letting us set arbitrary permissions
 * for filesystem access without changing the "normal" uids which
 * are used for other things.
 *
 * generic_permission is rcu-walk aware. It returns -ECHILD in case an rcu-walk
 * request cannot be satisfied (eg. requires blocking or too much complexity).
 * It would then be called again in ref-walk mode.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply pass @nop_mnt_idmap.
 */
int generic_permission(struct mnt_idmap *idmap, struct inode *inode,
               int mask)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

/**
 * do_inode_permission - UNIX permission checking
 * @idmap:  idmap of the mount the inode was found from
 * @inode:  inode to check permissions on
 * @mask:   right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC ...)
 *
 * We _really_ want to just do "generic_permission()" without
 * even looking at the inode->i_op values. So we keep a cache
 * flag in inode->i_opflags, that says "this has not special
 * permission function, use the fast case".
 */
static inline int do_inode_permission(struct mnt_idmap *idmap,
                      struct inode *inode, int mask)
{
    if (unlikely(!(inode->i_opflags & IOP_FASTPERM))) {
        if (likely(inode->i_op->permission))
            return inode->i_op->permission(idmap, inode, mask);

        /* This gets set once for the inode lifetime */
        spin_lock(&inode->i_lock);
        inode->i_opflags |= IOP_FASTPERM;
        spin_unlock(&inode->i_lock);
    }
    return generic_permission(idmap, inode, mask);
}

/**
 * inode_permission - Check for access rights to a given inode
 * @idmap:  idmap of the mount the inode was found from
 * @inode:  Inode to check permission on
 * @mask:   Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Check for read/write/execute permissions on an inode.  We use fs[ug]id for
 * this, letting us set arbitrary permissions for filesystem access without
 * changing the "normal" UIDs which are used for other things.
 *
 * When checking for MAY_APPEND, MAY_WRITE must also be set in @mask.
 */
int inode_permission(struct mnt_idmap *idmap,
             struct inode *inode, int mask)
{
    int retval;

    retval = sb_permission(inode->i_sb, inode, mask);
    if (retval)
        return retval;

    if (unlikely(mask & MAY_WRITE)) {
        /*
         * Nobody gets write access to an immutable file.
         */
        if (IS_IMMUTABLE(inode))
            return -EPERM;

        /*
         * Updating mtime will likely cause i_uid and i_gid to be
         * written back improperly if their true value is unknown
         * to the vfs.
         */
        if (HAS_UNMAPPED_ID(idmap, inode))
            return -EACCES;
    }

    retval = do_inode_permission(idmap, inode, mask);
    if (retval)
        return retval;

    retval = devcgroup_inode_permission(inode, mask);
    if (retval)
        return retval;

    return security_inode_permission(inode, mask);
}

static int may_open(struct mnt_idmap *idmap, const struct path *path,
            int acc_mode, int flag)
{
    struct dentry *dentry = path->dentry;
    struct inode *inode = dentry->d_inode;
    int error;

    if (!inode)
        return -ENOENT;

    switch (inode->i_mode & S_IFMT) {
    case S_IFLNK:
        return -ELOOP;
    case S_IFDIR:
        if (acc_mode & MAY_WRITE)
            return -EISDIR;
        if (acc_mode & MAY_EXEC)
            return -EACCES;
        break;
    case S_IFBLK:
    case S_IFCHR:
        if (!may_open_dev(path))
            return -EACCES;
        fallthrough;
    case S_IFIFO:
    case S_IFSOCK:
        if (acc_mode & MAY_EXEC)
            return -EACCES;
        flag &= ~O_TRUNC;
        break;
    case S_IFREG:
        if ((acc_mode & MAY_EXEC) && path_noexec(path))
            return -EACCES;
        break;
    }

    error = inode_permission(idmap, inode, MAY_OPEN | acc_mode);
    if (error)
        return error;

    /*
     * An append-only file must be opened in append mode for writing.
     */
    if (IS_APPEND(inode)) {
        if  ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND))
            return -EPERM;
        if (flag & O_TRUNC)
            return -EPERM;
    }

    /* O_NOATIME can only be set by the owner or superuser */
    if (flag & O_NOATIME && !inode_owner_or_capable(idmap, inode))
        return -EPERM;

    return 0;
}

/*
 * Handle the last step of open()
 */
static int do_open(struct nameidata *nd,
           struct file *file, const struct open_flags *op)
{
    struct mnt_idmap *idmap;
    int open_flag = op->open_flag;
    bool do_truncate;
    int acc_mode;
    int error;

    if (!(file->f_mode & (FMODE_OPENED | FMODE_CREATED))) {
        error = complete_walk(nd);
        if (error)
            return error;
    }
    if (!(file->f_mode & FMODE_CREATED))
        audit_inode(nd->name, nd->path.dentry, 0);
    idmap = mnt_idmap(nd->path.mnt);
    if (open_flag & O_CREAT) {
        if ((open_flag & O_EXCL) && !(file->f_mode & FMODE_CREATED))
            return -EEXIST;
        if (d_is_dir(nd->path.dentry))
            return -EISDIR;
        error = may_create_in_sticky(idmap, nd,
                         d_backing_inode(nd->path.dentry));
        if (unlikely(error))
            return error;
    }
    if ((nd->flags & LOOKUP_DIRECTORY) && !d_can_lookup(nd->path.dentry))
        return -ENOTDIR;

    do_truncate = false;
    acc_mode = op->acc_mode;
    if (file->f_mode & FMODE_CREATED) {
        /* Don't check for write permission, don't truncate */
        open_flag &= ~O_TRUNC;
        acc_mode = 0;
    } else if (d_is_reg(nd->path.dentry) && open_flag & O_TRUNC) {
        error = mnt_want_write(nd->path.mnt);
        if (error)
            return error;
        do_truncate = true;
    }
    error = may_open(idmap, &nd->path, acc_mode, open_flag);
    if (!error && !(file->f_mode & FMODE_OPENED))
        error = vfs_open(&nd->path, file);
    if (!error)
        error = security_file_post_open(file, op->acc_mode);
    if (!error && do_truncate)
        error = handle_truncate(idmap, file);
    if (unlikely(error > 0)) {
        WARN_ON(1);
        error = -EINVAL;
    }
    if (do_truncate)
        mnt_drop_write(nd->path.mnt);
    return error;
}

static struct file *path_openat(struct nameidata *nd,
            const struct open_flags *op, unsigned flags)
{
    struct file *file;
    int error;

    file = alloc_empty_file(op->open_flag, current_cred());
    if (IS_ERR(file))
        return file;

    if (unlikely(file->f_flags & __O_TMPFILE)) {
        error = do_tmpfile(nd, flags, op, file);
    } else if (unlikely(file->f_flags & O_PATH)) {
        error = do_o_path(nd, flags, file);
    } else {
        const char *s = path_init(nd, flags);
        while (!(error = link_path_walk(s, nd)) &&
               (s = open_last_lookups(nd, file, op)) != NULL)
            ;
        if (!error)
            error = do_open(nd, file, op);
        terminate_walk(nd);
    }
    if (likely(!error)) {
        if (likely(file->f_mode & FMODE_OPENED))
            return file;
        WARN_ON(1);
        error = -EINVAL;
    }
#if 0
    fput(file);
    if (error == -EOPENSTALE) {
        if (flags & LOOKUP_RCU)
            error = -ECHILD;
        else
            error = -ESTALE;
    }
    return ERR_PTR(error);
#endif

    PANIC("");
}

struct file *do_filp_open(int dfd, struct filename *pathname,
        const struct open_flags *op)
{
    struct nameidata nd;
    int flags = op->lookup_flags;
    struct file *filp;

    set_nameidata(&nd, dfd, pathname, NULL);
    filp = path_openat(&nd, op, flags | LOOKUP_RCU);
    if (unlikely(filp == ERR_PTR(-ECHILD)))
        filp = path_openat(&nd, op, flags);
    if (unlikely(filp == ERR_PTR(-ESTALE)))
        filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
    restore_nameidata();
    return filp;
}
