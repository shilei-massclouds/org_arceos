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

#define ND_ROOT_PRESET 1
#define ND_ROOT_GRABBED 2
#define ND_JUMPED 4

#ifndef LAST_WORD_IS_DOT
  #define LAST_WORD_IS_DOT  0x2e
  #define LAST_WORD_IS_DOTDOT   0x2e2e
#endif

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

enum {WALK_TRAILING = 1, WALK_MORE = 2, WALK_NOFOLLOW = 4};

static bool try_to_unlazy(struct nameidata *nd);

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

static inline int d_revalidate(struct dentry *dentry, unsigned int flags)
{
    if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE))
        return dentry->d_op->d_revalidate(dentry, flags);
    else
        return 1;
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

/*
 * Try to skip to top of mountpoint pile in rcuwalk mode.  Fail if
 * we meet a managed dentry that would need blocking.
 */
static bool __follow_mount_rcu(struct nameidata *nd, struct path *path)
{
    struct dentry *dentry = path->dentry;
    unsigned int flags = dentry->d_flags;

    if (likely(!(flags & DCACHE_MANAGED_DENTRY)))
        return true;

    if (unlikely(nd->flags & LOOKUP_NO_XDEV))
        return false;


    PANIC("");
}

static inline int traverse_mounts(struct path *path, bool *jumped,
                  int *count, unsigned lookup_flags)
{
    unsigned flags = smp_load_acquire(&path->dentry->d_flags);

    /* fastpath */
    if (likely(!(flags & DCACHE_MANAGED_DENTRY))) {
        *jumped = false;
        if (unlikely(d_flags_negative(flags)))
            return -ENOENT;
        return 0;
    }
#if 0
    return __traverse_mounts(path, flags, jumped, count, lookup_flags);
#endif
    PANIC("");
}

static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
              struct path *path)
{
    bool jumped;
    int ret;

    path->mnt = nd->path.mnt;
    path->dentry = dentry;
    if (nd->flags & LOOKUP_RCU) {
        unsigned int seq = nd->next_seq;
        if (likely(__follow_mount_rcu(nd, path)))
            return 0;
#if 0
        // *path and nd->next_seq might've been clobbered
        path->mnt = nd->path.mnt;
        path->dentry = dentry;
        nd->next_seq = seq;
        if (!try_to_unlazy_next(nd, dentry))
            return -ECHILD;
#endif
        PANIC("LOOKUP_RCU");
    }
    ret = traverse_mounts(path, &jumped, &nd->total_link_count, nd->flags);
    if (jumped) {
        if (unlikely(nd->flags & LOOKUP_NO_XDEV))
            ret = -EXDEV;
        else
            nd->state |= ND_JUMPED;
    }
    if (unlikely(ret)) {
        dput(path->dentry);
        if (path->mnt != nd->path.mnt)
            mntput(path->mnt);
    }
    return ret;
}

/*
 * Do we need to follow links? We _really_ want to be able
 * to do this check without having to look at inode->i_op,
 * so we keep a cache of "no, this doesn't need follow_link"
 * for the common case.
 *
 * NOTE: dentry must be what nd->next_seq had been sampled from.
 */
static const char *step_into(struct nameidata *nd, int flags,
             struct dentry *dentry)
{
    struct path path;
    struct inode *inode;
    int err = handle_mounts(nd, dentry, &path);

    if (err < 0)
        return ERR_PTR(err);
    inode = path.dentry->d_inode;
    if (likely(!d_is_symlink(path.dentry)) ||
       ((flags & WALK_TRAILING) && !(nd->flags & LOOKUP_FOLLOW)) ||
       (flags & WALK_NOFOLLOW)) {
        /* not a symlink or should not follow */
        if (nd->flags & LOOKUP_RCU) {
            if (read_seqcount_retry(&path.dentry->d_seq, nd->next_seq))
                return ERR_PTR(-ECHILD);
            if (unlikely(!inode))
                return ERR_PTR(-ENOENT);
        } else {
            dput(nd->path.dentry);
            if (nd->path.mnt != path.mnt)
                mntput(nd->path.mnt);
        }
        nd->path = path;
        nd->inode = inode;
        nd->seq = nd->next_seq;
        return NULL;
    }
#if 0
    if (nd->flags & LOOKUP_RCU) {
        /* make sure that d_is_symlink above matches inode */
        if (read_seqcount_retry(&path.dentry->d_seq, nd->next_seq))
            return ERR_PTR(-ECHILD);
    } else {
        if (path.mnt == nd->path.mnt)
            mntget(path.mnt);
    }
    return pick_link(nd, &path, inode, flags);
#endif
    PANIC("");
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

    /* Relative pathname -- get the starting-point it is relative to. */
    if (nd->dfd == AT_FDCWD) {
        PANIC("AT_FDCWD");
    } else {
        PANIC("no AT_FDCWD");
    }

    /* For scoped-lookups we need to set the root to the dirfd as well. */
    if (flags & LOOKUP_IS_SCOPED) {
        nd->root = nd->path;
        if (flags & LOOKUP_RCU) {
            nd->root_seq = nd->seq;
        } else {
            path_get(&nd->root);
            nd->state |= ND_ROOT_GRABBED;
        }
    }
    PANIC("");
    return s;
}

/**
 * lookup_fast - do fast lockless (but racy) lookup of a dentry
 * @nd: current nameidata
 *
 * Do a fast, but racy lookup in the dcache for the given dentry, and
 * revalidate it. Returns a valid dentry pointer or NULL if one wasn't
 * found. On error, an ERR_PTR will be returned.
 *
 * If this function returns a valid dentry and the walk is no longer
 * lazy, the dentry will carry a reference that must later be put. If
 * RCU mode is still in force, then this is not the case and the dentry
 * must be legitimized before use. If this returns NULL, then the walk
 * will no longer be in RCU mode.
 */
static struct dentry *lookup_fast(struct nameidata *nd)
{
    struct dentry *dentry, *parent = nd->path.dentry;
    int status = 1;

    /*
     * Rename seqlock is not required here because in the off chance
     * of a false negative due to a concurrent rename, the caller is
     * going to fall back to non-racy lookup.
     */
    if (nd->flags & LOOKUP_RCU) {
        dentry = __d_lookup_rcu(parent, &nd->last, &nd->next_seq);
        if (unlikely(!dentry)) {
            if (!try_to_unlazy(nd))
                return ERR_PTR(-ECHILD);
            return NULL;
        }

        /*
         * This sequence count validates that the parent had no
         * changes while we did the lookup of the dentry above.
         */
        if (read_seqcount_retry(&parent->d_seq, nd->seq))
            return ERR_PTR(-ECHILD);

        status = d_revalidate(dentry, nd->flags);
        if (likely(status > 0))
            return dentry;
#if 0
        if (!try_to_unlazy_next(nd, dentry))
            return ERR_PTR(-ECHILD);
        if (status == -ECHILD)
            /* we'd been told to redo it in non-rcu mode */
            status = d_revalidate(dentry, nd->flags);
#endif

        PANIC("LOOKUP_RCU");
    } else {
        PANIC("ELSE");
    }
    if (unlikely(status <= 0)) {
        if (!status)
            d_invalidate(dentry);
        dput(dentry);
        return ERR_PTR(status);
    }
    PANIC("");
    return dentry;
}

/* Fast lookup failed, do it the slow way */
static struct dentry *__lookup_slow(const struct qstr *name,
                    struct dentry *dir,
                    unsigned int flags)
{
    struct dentry *dentry, *old;
    struct inode *inode = dir->d_inode;
    DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

    /* Don't go there if it's already dead */
    if (unlikely(IS_DEADDIR(inode)))
        return ERR_PTR(-ENOENT);
again:
    dentry = d_alloc_parallel(dir, name, &wq);
    if (IS_ERR(dentry))
        return dentry;
    if (unlikely(!d_in_lookup(dentry))) {
        int error = d_revalidate(dentry, flags);
        if (unlikely(error <= 0)) {
            if (!error) {
                d_invalidate(dentry);
                dput(dentry);
                goto again;
            }
            dput(dentry);
            dentry = ERR_PTR(error);
        }
    } else {
        old = inode->i_op->lookup(inode, dentry, flags);
        d_lookup_done(dentry);
        if (unlikely(old)) {
            dput(dentry);
            dentry = old;
        }
    }
    return dentry;
}

static struct dentry *lookup_slow(const struct qstr *name,
                  struct dentry *dir,
                  unsigned int flags)
{
    struct inode *inode = dir->d_inode;
    struct dentry *res;
    inode_lock_shared(inode);
    res = __lookup_slow(name, dir, flags);
    inode_unlock_shared(inode);
    return res;
}

static const char *walk_component(struct nameidata *nd, int flags)
{
    struct dentry *dentry;
    /*
     * "." and ".." are special - ".." especially so because it has
     * to be able to know about the current root directory and
     * parent relationships.
     */
    if (unlikely(nd->last_type != LAST_NORM)) {
        if (!(flags & WALK_MORE) && nd->depth)
            put_link(nd);
        return handle_dots(nd, nd->last_type);
    }
    dentry = lookup_fast(nd);
    if (IS_ERR(dentry))
        return ERR_CAST(dentry);
    if (unlikely(!dentry)) {
        dentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);
        if (IS_ERR(dentry))
            return ERR_CAST(dentry);
    }
    if (!(flags & WALK_MORE) && nd->depth)
        put_link(nd);
    return step_into(nd, flags, dentry);
}

static inline int may_lookup(struct mnt_idmap *idmap,
                 struct nameidata *restrict nd)
{
    int err, mask;

    mask = nd->flags & LOOKUP_RCU ? MAY_NOT_BLOCK : 0;
    err = inode_permission(idmap, nd->inode, mask | MAY_EXEC);
    if (likely(!err))
        return 0;

    // If we failed, and we weren't in LOOKUP_RCU, it's final
    if (!(nd->flags & LOOKUP_RCU))
        return err;

    // Drop out of RCU mode to make sure it wasn't transient
    if (!try_to_unlazy(nd))
        return -ECHILD; // redo it all non-lazy

    if (err != -ECHILD) // hard error
        return err;

    return inode_permission(idmap, nd->inode, MAY_EXEC);
}

/*  Check whether we can create an object with dentry child in directory
 *  dir.
 *  1. We can't do it if child already exists (open has special treatment for
 *     this case, but since we are inlined it's OK)
 *  2. We can't do it if dir is read-only (done in permission())
 *  3. We can't do it if the fs can't represent the fsuid or fsgid.
 *  4. We should have write and exec permissions on dir
 *  5. We can't do it if dir is immutable (done in permission())
 */
static inline int may_create(struct mnt_idmap *idmap,
                 struct inode *dir, struct dentry *child)
{
    audit_inode_child(dir, child, AUDIT_TYPE_CHILD_CREATE);
    if (child->d_inode)
        return -EEXIST;
    if (IS_DEADDIR(dir))
        return -ENOENT;
    if (!fsuidgid_has_mapping(dir->i_sb, idmap))
        return -EOVERFLOW;

    return inode_permission(idmap, dir, MAY_WRITE | MAY_EXEC);
}

/*
 * We know there's a real path component here of at least
 * one character.
 */
static inline const char *hash_name(struct nameidata *nd, const char *name, unsigned long *lastword)
{
    unsigned long hash = init_name_hash(nd->path.dentry);
    unsigned long len = 0, c, last = 0;

    c = (unsigned char)*name;
    do {
        last = (last << 8) + c;
        len++;
        hash = partial_name_hash(c, hash);
        c = (unsigned char)name[len];
    } while (c && c != '/');

    // This is reliable for DOT or DOTDOT, since the component
    // cannot contain NUL characters - top bits being zero means
    // we cannot have had any other pathnames.
    *lastword = last;
    nd->last.hash = end_name_hash(hash);
    nd->last.len = len;
    return name + len;
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
        struct mnt_idmap *idmap;
        const char *link;
        unsigned long lastword;

        idmap = mnt_idmap(nd->path.mnt);
        err = may_lookup(idmap, nd);
        if (err)
            return err;

        nd->last.name = name;
        name = hash_name(nd, name, &lastword);

        switch(lastword) {
        case LAST_WORD_IS_DOTDOT:
            nd->last_type = LAST_DOTDOT;
            nd->state |= ND_JUMPED;
            break;

        case LAST_WORD_IS_DOT:
            nd->last_type = LAST_DOT;
            break;

        default:
            nd->last_type = LAST_NORM;
            nd->state &= ~ND_JUMPED;

            struct dentry *parent = nd->path.dentry;
            if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
                err = parent->d_op->d_hash(parent, &nd->last);
                if (err < 0)
                    return err;
            }
        }

        if (!*name)
            goto OK;
        /*
         * If it wasn't NUL, we know it was '/'. Skip that
         * slash, and continue until no more slashes.
         */
        do {
            name++;
        } while (unlikely(*name == '/'));
        if (unlikely(!*name)) {
OK:
            /* pathname or trailing symlink, done */
            if (!depth) {
                nd->dir_vfsuid = i_uid_into_vfsuid(idmap, nd->inode);
                nd->dir_mode = nd->inode->i_mode;
                nd->flags &= ~LOOKUP_PARENT;
                return 0;
            }
            /* last component of nested symlink */
            name = nd->stack[--depth].name;
            link = walk_component(nd, 0);
        } else {
            /* not the last component */
            link = walk_component(nd, WALK_MORE);
        }
        if (unlikely(link)) {
            if (IS_ERR(link))
                return PTR_ERR(link);
            /* a symlink to follow */
            nd->stack[depth++].name = name;
            name = link;
            continue;
        }
        if (unlikely(!d_can_lookup(nd->path.dentry))) {
            if (nd->flags & LOOKUP_RCU) {
                if (!try_to_unlazy(nd))
                    return -ECHILD;
            }
            return -ENOTDIR;
        }
    }
}

static inline const char *lookup_last(struct nameidata *nd)
{
    if (nd->last_type == LAST_NORM && nd->last.name[nd->last.len])
        nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

    return walk_component(nd, WALK_TRAILING);
}

static int handle_lookup_down(struct nameidata *nd)
{
    if (!(nd->flags & LOOKUP_RCU))
        dget(nd->path.dentry);
    nd->next_seq = nd->seq;
    return PTR_ERR(step_into(nd, WALK_NOFOLLOW, nd->path.dentry));
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

static void drop_links(struct nameidata *nd)
{
    int i = nd->depth;
    while (i--) {
        struct saved *last = nd->stack + i;
        do_delayed_call(&last->done);
        clear_delayed_call(&last->done);
    }
}

static void leave_rcu(struct nameidata *nd)
{
    nd->flags &= ~LOOKUP_RCU;
    nd->seq = nd->next_seq = 0;
    rcu_read_unlock();
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

/* Returns 0 and nd will be valid on success; Returns error, otherwise. */
static int path_lookupat(struct nameidata *nd, unsigned flags, struct path *path)
{
    const char *s = path_init(nd, flags);
    int err;

    if (unlikely(flags & LOOKUP_DOWN) && !IS_ERR(s)) {
#if 0
        err = handle_lookup_down(nd);
        if (unlikely(err < 0))
            s = ERR_PTR(err);
#endif
        PANIC("LOOKUP_DOWN");
    }

    while (!(err = link_path_walk(s, nd)) &&
           (s = lookup_last(nd)) != NULL)
        ;
    if (!err && unlikely(nd->flags & LOOKUP_MOUNTPOINT)) {
        err = handle_lookup_down(nd);
        nd->state &= ~ND_JUMPED; // no d_weak_revalidate(), please...
    }
    if (!err)
        err = complete_walk(nd);

    if (!err && nd->flags & LOOKUP_DIRECTORY)
        if (!d_can_lookup(nd->path.dentry))
            err = -ENOTDIR;
    if (!err) {
        *path = nd->path;
        nd->path.mnt = NULL;
        nd->path.dentry = NULL;
    }
    terminate_walk(nd);
    return err;
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
    struct path path;
    int error = path_lookupat(nd, flags, &path);
    if (!error) {
        audit_inode(nd->name, path.dentry, 0);
        error = vfs_open(&path, file);
        path_put(&path);
    }
    return error;
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

/**
 * vfs_prepare_mode - prepare the mode to be used for a new inode
 * @idmap:  idmap of the mount the inode was found from
 * @dir:    parent directory of the new inode
 * @mode:   mode of the new inode
 * @mask_perms: allowed permission by the vfs
 * @type:   type of file to be created
 *
 * This helper consolidates and enforces vfs restrictions on the @mode of a new
 * object to be created.
 *
 * Umask stripping depends on whether the filesystem supports POSIX ACLs (see
 * the kernel documentation for mode_strip_umask()). Moving umask stripping
 * after setgid stripping allows the same ordering for both non-POSIX ACL and
 * POSIX ACL supporting filesystems.
 *
 * Note that it's currently valid for @type to be 0 if a directory is created.
 * Filesystems raise that flag individually and we need to check whether each
 * filesystem can deal with receiving S_IFDIR from the vfs before we enforce a
 * non-zero type.
 *
 * Returns: mode to be passed to the filesystem
 */
static inline umode_t vfs_prepare_mode(struct mnt_idmap *idmap,
                       const struct inode *dir, umode_t mode,
                       umode_t mask_perms, umode_t type)
{
    mode = mode_strip_sgid(idmap, dir, mode);
    mode = mode_strip_umask(dir, mode);

    /*
     * Apply the vfs mandated allowed permission mask and set the type of
     * file to be created before we call into the filesystem.
     */
    mode &= (mask_perms & ~S_IFMT);
    mode |= (type & S_IFMT);

    return mode;
}

static int may_o_create(struct mnt_idmap *idmap,
            const struct path *dir, struct dentry *dentry,
            umode_t mode)
{
    int error = security_path_mknod(dir, dentry, mode, 0);
    if (error)
        return error;

    if (!fsuidgid_has_mapping(dir->dentry->d_sb, idmap))
        return -EOVERFLOW;

    error = inode_permission(idmap, dir->dentry->d_inode,
                 MAY_WRITE | MAY_EXEC);
    if (error)
        return error;

    return security_inode_create(dir->dentry->d_inode, dentry, mode);
}

/*
 * Attempt to atomically look up, create and open a file from a negative
 * dentry.
 *
 * Returns 0 if successful.  The file will have been created and attached to
 * @file by the filesystem calling finish_open().
 *
 * If the file was looked up only or didn't need creating, FMODE_OPENED won't
 * be set.  The caller will need to perform the open themselves.  @path will
 * have been updated to point to the new dentry.  This may be negative.
 *
 * Returns an error code otherwise.
 */
static struct dentry *atomic_open(struct nameidata *nd, struct dentry *dentry,
                  struct file *file,
                  int open_flag, umode_t mode)
{
    struct dentry *const DENTRY_NOT_SET = (void *) -1UL;
    struct inode *dir =  nd->path.dentry->d_inode;
    int error;

    PANIC("");
}

/*
 * Look up and maybe create and open the last component.
 *
 * Must be called with parent locked (exclusive in O_CREAT case).
 *
 * Returns 0 on success, that is, if
 *  the file was successfully atomically created (if necessary) and opened, or
 *  the file was not completely opened at this time, though lookups and
 *  creations were performed.
 * These case are distinguished by presence of FMODE_OPENED on file->f_mode.
 * In the latter case dentry returned in @path might be negative if O_CREAT
 * hadn't been specified.
 *
 * An error code is returned on failure.
 */
static struct dentry *lookup_open(struct nameidata *nd, struct file *file,
                  const struct open_flags *op,
                  bool got_write)
{
    struct mnt_idmap *idmap;
    struct dentry *dir = nd->path.dentry;
    struct inode *dir_inode = dir->d_inode;
    int open_flag = op->open_flag;
    struct dentry *dentry;
    int error, create_error = 0;
    umode_t mode = op->mode;
    DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

    if (unlikely(IS_DEADDIR(dir_inode)))
        return ERR_PTR(-ENOENT);

    file->f_mode &= ~FMODE_CREATED;
    dentry = d_lookup(dir, &nd->last);
    for (;;) {
        if (!dentry) {
            dentry = d_alloc_parallel(dir, &nd->last, &wq);
            if (IS_ERR(dentry))
                return dentry;
        }
        if (d_in_lookup(dentry))
            break;

        error = d_revalidate(dentry, nd->flags);
        if (likely(error > 0))
            break;
        if (error)
            goto out_dput;
        d_invalidate(dentry);
        dput(dentry);
        dentry = NULL;

        PANIC("LOOP");
    }
    if (dentry->d_inode) {
        /* Cached positive dentry: will open in f_op->open */
        return dentry;
    }

    if (open_flag & O_CREAT)
        audit_inode(nd->name, dir, AUDIT_INODE_PARENT);

    /*
     * Checking write permission is tricky, bacuse we don't know if we are
     * going to actually need it: O_CREAT opens should work as long as the
     * file exists.  But checking existence breaks atomicity.  The trick is
     * to check access and if not granted clear O_CREAT from the flags.
     *
     * Another problem is returing the "right" error value (e.g. for an
     * O_EXCL open we want to return EEXIST not EROFS).
     */
    if (unlikely(!got_write))
        open_flag &= ~O_TRUNC;
    idmap = mnt_idmap(nd->path.mnt);
    if (open_flag & O_CREAT) {
        if (open_flag & O_EXCL)
            open_flag &= ~O_TRUNC;
        mode = vfs_prepare_mode(idmap, dir->d_inode, mode, mode, mode);
        if (likely(got_write))
            create_error = may_o_create(idmap, &nd->path,
                            dentry, mode);
        else
            create_error = -EROFS;
    }
    if (create_error)
        open_flag &= ~O_CREAT;
    if (dir_inode->i_op->atomic_open) {
        dentry = atomic_open(nd, dentry, file, open_flag, mode);
        if (unlikely(create_error) && dentry == ERR_PTR(-ENOENT))
            dentry = ERR_PTR(create_error);
        return dentry;
    }

    if (d_in_lookup(dentry)) {
        struct dentry *res = dir_inode->i_op->lookup(dir_inode, dentry,
                                 nd->flags);
        d_lookup_done(dentry);
        if (unlikely(res)) {
            if (IS_ERR(res)) {
                error = PTR_ERR(res);
                goto out_dput;
            }
            dput(dentry);
            dentry = res;
        }
    }

    /* Negative dentry, just create the file */
    if (!dentry->d_inode && (open_flag & O_CREAT)) {
        file->f_mode |= FMODE_CREATED;
        audit_inode_child(dir_inode, dentry, AUDIT_TYPE_CHILD_CREATE);
        if (!dir_inode->i_op->create) {
            error = -EACCES;
            goto out_dput;
        }

        error = dir_inode->i_op->create(idmap, dir_inode, dentry,
                        mode, open_flag & O_EXCL);
        if (error)
            goto out_dput;
    }
    if (unlikely(create_error) && !dentry->d_inode) {
        error = create_error;
        goto out_dput;
    }

    return dentry;

out_dput:
    dput(dentry);
    return ERR_PTR(error);
}

static inline bool trailing_slashes(struct nameidata *nd)
{
    return (bool)nd->last.name[nd->last.len];
}

static struct dentry *lookup_fast_for_open(struct nameidata *nd, int open_flag)
{
    struct dentry *dentry;

    if (open_flag & O_CREAT) {
        if (trailing_slashes(nd))
            return ERR_PTR(-EISDIR);

        /* Don't bother on an O_EXCL create */
        if (open_flag & O_EXCL)
            return NULL;
    }

    if (trailing_slashes(nd))
        nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

    dentry = lookup_fast(nd);
    if (IS_ERR_OR_NULL(dentry))
        return dentry;

    if (open_flag & O_CREAT) {
        /* Discard negative dentries. Need inode_lock to do the create */
        if (!dentry->d_inode) {
            if (!(nd->flags & LOOKUP_RCU))
                dput(dentry);
            dentry = NULL;
        }
    }
    return dentry;
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

    /* We _can_ be in RCU mode here */
    dentry = lookup_fast_for_open(nd, open_flag);
    if (IS_ERR(dentry))
        return ERR_CAST(dentry);

    if (likely(dentry))
        goto finish_lookup;

    if (!(open_flag & O_CREAT)) {
        if (WARN_ON_ONCE(nd->flags & LOOKUP_RCU))
            return ERR_PTR(-ECHILD);
    } else {
        if (nd->flags & LOOKUP_RCU) {
            if (!try_to_unlazy(nd))
                return ERR_PTR(-ECHILD);
        }
    }

    if (open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) {
        got_write = !mnt_want_write(nd->path.mnt);
        /*
         * do _not_ fail yet - we might not need that or fail with
         * a different error; let lookup_open() decide; we'll be
         * dropping this one anyway.
         */
    }
    if (open_flag & O_CREAT)
        inode_lock(dir->d_inode);
    else
        inode_lock_shared(dir->d_inode);
    dentry = lookup_open(nd, file, op, got_write);
    if (!IS_ERR(dentry)) {
        if (file->f_mode & FMODE_CREATED)
            fsnotify_create(dir->d_inode, dentry);
        if (file->f_mode & FMODE_OPENED)
            fsnotify_open(file);
    }
    if (open_flag & O_CREAT)
        inode_unlock(dir->d_inode);
    else
        inode_unlock_shared(dir->d_inode);

    if (got_write)
        mnt_drop_write(nd->path.mnt);

    if (IS_ERR(dentry))
        return ERR_CAST(dentry);

    if (file->f_mode & (FMODE_OPENED | FMODE_CREATED)) {
        dput(nd->path.dentry);
        nd->path.dentry = dentry;
        return NULL;
    }

finish_lookup:
    if (nd->depth)
        put_link(nd);
    res = step_into(nd, WALK_TRAILING, dentry);
    if (unlikely(res))
        nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
    return res;
}

/*
 *  Check whether we can remove a link victim from directory dir, check
 *  whether the type of victim is right.
 *  1. We can't do it if dir is read-only (done in permission())
 *  2. We should have write and exec permissions on dir
 *  3. We can't remove anything from append-only dir
 *  4. We can't do anything with immutable dir (done in permission())
 *  5. If the sticky bit on dir is set we should either
 *  a. be owner of dir, or
 *  b. be owner of victim, or
 *  c. have CAP_FOWNER capability
 *  6. If the victim is append-only or immutable we can't do antyhing with
 *     links pointing to it.
 *  7. If the victim has an unknown uid or gid we can't change the inode.
 *  8. If we were asked to remove a directory and victim isn't one - ENOTDIR.
 *  9. If we were asked to remove a non-directory and victim isn't one - EISDIR.
 * 10. We can't remove a root or mountpoint.
 * 11. We don't allow removal of NFS sillyrenamed files; it's handled by
 *     nfs_async_unlink().
 */
static int may_delete(struct mnt_idmap *idmap, struct inode *dir,
              struct dentry *victim, bool isdir)
{
    struct inode *inode = d_backing_inode(victim);
    int error;

    if (d_is_negative(victim))
        return -ENOENT;
    BUG_ON(!inode);

    BUG_ON(victim->d_parent->d_inode != dir);

    /* Inode writeback is not safe when the uid or gid are invalid. */
    if (!vfsuid_valid(i_uid_into_vfsuid(idmap, inode)) ||
        !vfsgid_valid(i_gid_into_vfsgid(idmap, inode)))
        return -EOVERFLOW;

    audit_inode_child(dir, victim, AUDIT_TYPE_CHILD_DELETE);

    error = inode_permission(idmap, dir, MAY_WRITE | MAY_EXEC);
    if (error)
        return error;
    if (IS_APPEND(dir))
        return -EPERM;

    if (check_sticky(idmap, dir, inode) || IS_APPEND(inode) ||
        IS_IMMUTABLE(inode) || IS_SWAPFILE(inode) ||
        HAS_UNMAPPED_ID(idmap, inode))
        return -EPERM;
    if (isdir) {
        if (!d_is_dir(victim))
            return -ENOTDIR;
        if (IS_ROOT(victim))
            return -EBUSY;
    } else if (d_is_dir(victim))
        return -EISDIR;
    if (IS_DEADDIR(dir))
        return -ENOENT;
    if (victim->d_flags & DCACHE_NFSFS_RENAMED)
        return -EBUSY;
    return 0;
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
    umode_t dir_mode = nd->dir_mode;
    vfsuid_t dir_vfsuid = nd->dir_vfsuid, i_vfsuid;

    if (likely(!(dir_mode & S_ISVTX)))
        return 0;


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
    pr_notice("%s: No impl.", __func__);
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
    fput(file);
    if (error == -EOPENSTALE) {
        if (flags & LOOKUP_RCU)
            error = -ECHILD;
        else
            error = -ESTALE;
    }
    return ERR_PTR(error);
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

int cl_sys_unlink(const char *pathname)
{
    return do_unlinkat(AT_FDCWD, getname(pathname));
}

/* Returns 0 and nd will be valid on success; Returns error, otherwise. */
static int path_parentat(struct nameidata *nd, unsigned flags,
                struct path *parent)
{
    const char *s = path_init(nd, flags);
    int err = link_path_walk(s, nd);
    if (!err)
        err = complete_walk(nd);
    if (!err) {
        *parent = nd->path;
        nd->path.mnt = NULL;
        nd->path.dentry = NULL;
    }
    terminate_walk(nd);
    return err;
}

/* Note: this does not consume "name" */
static int __filename_parentat(int dfd, struct filename *name,
                   unsigned int flags, struct path *parent,
                   struct qstr *last, int *type,
                   const struct path *root)
{
    int retval;
    struct nameidata nd;

    if (IS_ERR(name))
        return PTR_ERR(name);
    set_nameidata(&nd, dfd, name, root);
    retval = path_parentat(&nd, flags | LOOKUP_RCU, parent);
    if (unlikely(retval == -ECHILD))
        retval = path_parentat(&nd, flags, parent);
    if (unlikely(retval == -ESTALE))
        retval = path_parentat(&nd, flags | LOOKUP_REVAL, parent);
    if (likely(!retval)) {
        *last = nd.last;
        *type = nd.last_type;
        audit_inode(name, parent->dentry, AUDIT_INODE_PARENT);
    }
    restore_nameidata();
    return retval;
}

static int filename_parentat(int dfd, struct filename *name,
                 unsigned int flags, struct path *parent,
                 struct qstr *last, int *type)
{
    return __filename_parentat(dfd, name, flags, parent, last, type, NULL);
}

/*
 * Make sure that the actual truncation of the file will occur outside its
 * directory's i_mutex.  Truncate can take a long time if there is a lot of
 * writeout happening, and we don't want to prevent access to the directory
 * while waiting on the I/O.
 */
int do_unlinkat(int dfd, struct filename *name)
{
    int error;
    struct dentry *dentry;
    struct path path;
    struct qstr last;
    int type;
    struct inode *inode = NULL;
    struct inode *delegated_inode = NULL;
    unsigned int lookup_flags = 0;
retry:
    error = filename_parentat(dfd, name, lookup_flags, &path, &last, &type);
    if (error)
        goto exit1;

    error = -EISDIR;
    if (type != LAST_NORM)
        goto exit2;

    error = mnt_want_write(path.mnt);
    if (error)
        goto exit2;
retry_deleg:
    inode_lock_nested(path.dentry->d_inode, I_MUTEX_PARENT);
    dentry = lookup_one_qstr_excl(&last, path.dentry, lookup_flags);
    error = PTR_ERR(dentry);
    if (!IS_ERR(dentry)) {

        /* Why not before? Because we want correct error value */
        if (last.name[last.len] || d_is_negative(dentry))
            goto slashes;
        inode = dentry->d_inode;
        ihold(inode);
        error = security_path_unlink(&path, dentry);
        if (error)
            goto exit3;
        error = vfs_unlink(mnt_idmap(path.mnt), path.dentry->d_inode,
                   dentry, &delegated_inode);
exit3:
        dput(dentry);
    }
    inode_unlock(path.dentry->d_inode);
    if (inode)
        iput(inode);    /* truncate the inode here */
    inode = NULL;
    if (delegated_inode) {
        error = break_deleg_wait(&delegated_inode);
        if (!error)
            goto retry_deleg;
    }
    mnt_drop_write(path.mnt);
exit2:
    path_put(&path);
    if (retry_estale(error, lookup_flags)) {
        lookup_flags |= LOOKUP_REVAL;
        inode = NULL;
        goto retry;
    }
exit1:
    putname(name);
    return error;

slashes:
    if (d_is_negative(dentry))
        error = -ENOENT;
    else if (d_is_dir(dentry))
        error = -EISDIR;
    else
        error = -ENOTDIR;
    goto exit3;
}

/*
 * This looks up the name in dcache and possibly revalidates the found dentry.
 * NULL is returned if the dentry does not exist in the cache.
 */
static struct dentry *lookup_dcache(const struct qstr *name,
                    struct dentry *dir,
                    unsigned int flags)
{
    struct dentry *dentry = d_lookup(dir, name);
    if (dentry) {
        int error = d_revalidate(dentry, flags);
        if (unlikely(error <= 0)) {
            if (!error)
                d_invalidate(dentry);
            dput(dentry);
            return ERR_PTR(error);
        }
    }
    return dentry;
}

/*
 * Parent directory has inode locked exclusive.  This is one
 * and only case when ->lookup() gets called on non in-lookup
 * dentries - as the matter of fact, this only gets called
 * when directory is guaranteed to have no in-lookup children
 * at all.
 */
struct dentry *lookup_one_qstr_excl(const struct qstr *name,
                    struct dentry *base,
                    unsigned int flags)
{
    struct dentry *dentry = lookup_dcache(name, base, flags);
    struct dentry *old;
    struct inode *dir = base->d_inode;

    if (dentry)
        return dentry;

    /* Don't create child dentry for a dead directory. */
    if (unlikely(IS_DEADDIR(dir)))
        return ERR_PTR(-ENOENT);

    dentry = d_alloc(base, name);
    if (unlikely(!dentry))
        return ERR_PTR(-ENOMEM);

    old = dir->i_op->lookup(dir, dentry, flags);
    if (unlikely(old)) {
        dput(dentry);
        dentry = old;
    }
    return dentry;
}

/**
 * vfs_unlink - unlink a filesystem object
 * @idmap:  idmap of the mount the inode was found from
 * @dir:    parent directory
 * @dentry: victim
 * @delegated_inode: returns victim inode, if the inode is delegated.
 *
 * The caller must hold dir->i_mutex.
 *
 * If vfs_unlink discovers a delegation, it will return -EWOULDBLOCK and
 * return a reference to the inode in delegated_inode.  The caller
 * should then break the delegation on that inode and retry.  Because
 * breaking a delegation may take a long time, the caller should drop
 * dir->i_mutex before doing so.
 *
 * Alternatively, a caller may pass NULL for delegated_inode.  This may
 * be appropriate for callers that expect the underlying filesystem not
 * to be NFS exported.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply pass @nop_mnt_idmap.
 */
int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir,
           struct dentry *dentry, struct inode **delegated_inode)
{
    struct inode *target = dentry->d_inode;
    int error = may_delete(idmap, dir, dentry, 0);

    if (error)
        return error;

    if (!dir->i_op->unlink)
        return -EPERM;

    inode_lock(target);
    if (IS_SWAPFILE(target))
        error = -EPERM;
    else if (is_local_mountpoint(dentry))
        error = -EBUSY;
    else {
        error = security_inode_unlink(dir, dentry);
        if (!error) {
            error = try_break_deleg(target, delegated_inode);
            if (error)
                goto out;
            error = dir->i_op->unlink(dir, dentry);
            if (!error) {
                dont_mount(dentry);
                detach_mounts(dentry);
            }
        }
    }
out:
    inode_unlock(target);

    /* We don't d_delete() NFS sillyrenamed files--they still exist. */
    if (!error && dentry->d_flags & DCACHE_NFSFS_RENAMED) {
        fsnotify_unlink(dir, dentry);
    } else if (!error) {
        fsnotify_link_count(target);
        d_delete_notify(dir, dentry);
    }

    return error;
}

int __check_sticky(struct mnt_idmap *idmap, struct inode *dir,
           struct inode *inode)
{
#if 0
    kuid_t fsuid = current_fsuid();

    if (vfsuid_eq_kuid(i_uid_into_vfsuid(idmap, inode), fsuid))
        return 0;
    if (vfsuid_eq_kuid(i_uid_into_vfsuid(idmap, dir), fsuid))
        return 0;
    return !capable_wrt_inode_uidgid(idmap, inode, CAP_FOWNER);
#endif
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int filename_lookup(int dfd, struct filename *name, unsigned flags,
            struct path *path, struct path *root)
{
    int retval;
    struct nameidata nd;
    if (IS_ERR(name))
        return PTR_ERR(name);
    set_nameidata(&nd, dfd, name, root);
    retval = path_lookupat(&nd, flags | LOOKUP_RCU, path);
    if (unlikely(retval == -ECHILD))
        retval = path_lookupat(&nd, flags, path);
    if (unlikely(retval == -ESTALE))
        retval = path_lookupat(&nd, flags | LOOKUP_REVAL, path);

    if (likely(!retval))
        audit_inode(name, path->dentry,
                flags & LOOKUP_MOUNTPOINT ? AUDIT_INODE_NOEVAL : 0);
    restore_nameidata();
    return retval;
}

int cl_sys_mkdir(const char *pathname, umode_t mode)
{
    return do_mkdirat(AT_FDCWD, getname(pathname), mode);
}

static struct dentry *filename_create(int dfd, struct filename *name,
                      struct path *path, unsigned int lookup_flags)
{
    struct dentry *dentry = ERR_PTR(-EEXIST);
    struct qstr last;
    bool want_dir = lookup_flags & LOOKUP_DIRECTORY;
    unsigned int reval_flag = lookup_flags & LOOKUP_REVAL;
    unsigned int create_flags = LOOKUP_CREATE | LOOKUP_EXCL;
    int type;
    int err2;
    int error;

    error = filename_parentat(dfd, name, reval_flag, path, &last, &type);
    if (error)
        return ERR_PTR(error);

    /*
     * Yucky last component or no last component at all?
     * (foo/., foo/.., /////)
     */
    if (unlikely(type != LAST_NORM))
        goto out;

    /* don't fail immediately if it's r/o, at least try to report other errors */
    err2 = mnt_want_write(path->mnt);
    /*
     * Do the final lookup.  Suppress 'create' if there is a trailing
     * '/', and a directory wasn't requested.
     */
    if (last.name[last.len] && !want_dir)
        create_flags = 0;
    inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);
    dentry = lookup_one_qstr_excl(&last, path->dentry,
                      reval_flag | create_flags);
    if (IS_ERR(dentry))
        goto unlock;

    error = -EEXIST;
    if (d_is_positive(dentry))
        goto fail;

    /*
     * Special case - lookup gave negative, but... we had foo/bar/
     * From the vfs_mknod() POV we just have a negative dentry -
     * all is fine. Let's be bastards - you had / on the end, you've
     * been asking for (non-existent) directory. -ENOENT for you.
     */
    if (unlikely(!create_flags)) {
        error = -ENOENT;
        goto fail;
    }
    if (unlikely(err2)) {
        error = err2;
        goto fail;
    }
    return dentry;
fail:
    dput(dentry);
    dentry = ERR_PTR(error);
unlock:
    inode_unlock(path->dentry->d_inode);
    if (!err2)
        mnt_drop_write(path->mnt);
out:
    path_put(path);
    PANIC("fail");
    return dentry;
}

int do_mkdirat(int dfd, struct filename *name, umode_t mode)
{
    struct dentry *dentry;
    struct path path;
    int error;
    unsigned int lookup_flags = LOOKUP_DIRECTORY;

retry:
    dentry = filename_create(dfd, name, &path, lookup_flags);
    error = PTR_ERR(dentry);
    if (IS_ERR(dentry))
        goto out_putname;

    error = security_path_mkdir(&path, dentry,
            mode_strip_umask(path.dentry->d_inode, mode));
    if (!error) {
        error = vfs_mkdir(mnt_idmap(path.mnt), path.dentry->d_inode,
                  dentry, mode);
    }
    done_path_create(&path, dentry);
    if (retry_estale(error, lookup_flags)) {
        lookup_flags |= LOOKUP_REVAL;
        goto retry;
    }
out_putname:
    putname(name);
    return error;
}

/**
 * vfs_mkdir - create directory
 * @idmap:  idmap of the mount the inode was found from
 * @dir:    inode of the parent directory
 * @dentry: dentry of the child directory
 * @mode:   mode of the child directory
 *
 * Create a directory.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply pass @nop_mnt_idmap.
 */
int vfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
          struct dentry *dentry, umode_t mode)
{
    int error;
    unsigned max_links = dir->i_sb->s_max_links;

    error = may_create(idmap, dir, dentry);
    if (error)
        return error;

    if (!dir->i_op->mkdir)
        return -EPERM;

    mode = vfs_prepare_mode(idmap, dir, mode, S_IRWXUGO | S_ISVTX, 0);
    error = security_inode_mkdir(dir, dentry, mode);
    if (error)
        return error;

    if (max_links && dir->i_nlink >= max_links)
        return -EMLINK;

    error = dir->i_op->mkdir(idmap, dir, dentry, mode);
    if (!error)
        fsnotify_mkdir(dir, dentry);
    return error;
}

void done_path_create(struct path *path, struct dentry *dentry)
{
    dput(dentry);
    inode_unlock(path->dentry->d_inode);
    mnt_drop_write(path->mnt);
    path_put(path);
}

int cl_sys_rmdir(const char *pathname)
{
    return do_rmdir(AT_FDCWD, getname(pathname));
}

int do_rmdir(int dfd, struct filename *name)
{
    int error;
    struct dentry *dentry;
    struct path path;
    struct qstr last;
    int type;
    unsigned int lookup_flags = 0;
retry:
    error = filename_parentat(dfd, name, lookup_flags, &path, &last, &type);
    if (error)
        goto exit1;

    switch (type) {
    case LAST_DOTDOT:
        error = -ENOTEMPTY;
        goto exit2;
    case LAST_DOT:
        error = -EINVAL;
        goto exit2;
    case LAST_ROOT:
        error = -EBUSY;
        goto exit2;
    }

    error = mnt_want_write(path.mnt);
    if (error)
        goto exit2;

    inode_lock_nested(path.dentry->d_inode, I_MUTEX_PARENT);
    dentry = lookup_one_qstr_excl(&last, path.dentry, lookup_flags);
    error = PTR_ERR(dentry);
    if (IS_ERR(dentry))
        goto exit3;
    if (!dentry->d_inode) {
        error = -ENOENT;
        goto exit4;
    }
    error = security_path_rmdir(&path, dentry);
    if (error)
        goto exit4;
    error = vfs_rmdir(mnt_idmap(path.mnt), path.dentry->d_inode, dentry);
exit4:
    dput(dentry);
exit3:
    inode_unlock(path.dentry->d_inode);
    mnt_drop_write(path.mnt);
exit2:
    path_put(&path);
    if (retry_estale(error, lookup_flags)) {
        lookup_flags |= LOOKUP_REVAL;
        goto retry;
    }
exit1:
    putname(name);
    return error;
}

/**
 * vfs_rmdir - remove directory
 * @idmap:  idmap of the mount the inode was found from
 * @dir:    inode of the parent directory
 * @dentry: dentry of the child directory
 *
 * Remove a directory.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply pass @nop_mnt_idmap.
 */
int vfs_rmdir(struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry)
{
    int error = may_delete(idmap, dir, dentry, 1);

    if (error)
        return error;

    if (!dir->i_op->rmdir)
        return -EPERM;

    dget(dentry);
    inode_lock(dentry->d_inode);

    error = -EBUSY;
    if (is_local_mountpoint(dentry) ||
        (dentry->d_inode->i_flags & S_KERNEL_FILE))
        goto out;

    error = security_inode_rmdir(dir, dentry);
    if (error)
        goto out;

    error = dir->i_op->rmdir(dir, dentry);
    if (error)
        goto out;

    shrink_dcache_parent(dentry);
    dentry->d_inode->i_flags |= S_DEAD;
    dont_mount(dentry);
    detach_mounts(dentry);

out:
    inode_unlock(dentry->d_inode);
    dput(dentry);
    if (!error)
        d_delete_notify(dir, dentry);
    return error;
}
