#include <linux/blkdev.h>
#include <linux/export.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/vfs.h>
#include <linux/quotaops.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/exportfs.h>
#include <linux/iversion.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h> /* sync_mapping_buffers */
#include <linux/fs_context.h>
#include <linux/pseudo_fs.h>
#include <linux/fsnotify.h>
#include <linux/unicode.h>
#include <linux/fscrypt.h>
#include <linux/pidfs.h>

#include <linux/uaccess.h>

#include "internal.h"

#include "../adaptor.h"

int simple_statfs(struct dentry *dentry, struct kstatfs *buf)
{
#if 0
    u64 id = huge_encode_dev(dentry->d_sb->s_dev);

    buf->f_fsid = u64_to_fsid(id);
    buf->f_type = dentry->d_sb->s_magic;
    buf->f_bsize = PAGE_SIZE;
    buf->f_namelen = NAME_MAX;
    return 0;
#endif
    PANIC("");
}

static const struct super_operations simple_super_operations = {
    .statfs     = simple_statfs,
};

static int pseudo_fs_fill_super(struct super_block *s, struct fs_context *fc)
{
    struct pseudo_fs_context *ctx = fc->fs_private;
    struct inode *root;

    s->s_maxbytes = MAX_LFS_FILESIZE;
    s->s_blocksize = PAGE_SIZE;
    s->s_blocksize_bits = PAGE_SHIFT;
    s->s_magic = ctx->magic;
    s->s_op = ctx->ops ?: &simple_super_operations;
    s->s_xattr = ctx->xattr;
    s->s_time_gran = 1;
    root = new_inode(s);
    if (!root)
        return -ENOMEM;

    /*
     * since this is the first inode, make it number 1. New inodes created
     * after this must take care not to collide with it (by passing
     * max_reserved of 1 to iunique).
     */
    root->i_ino = 1;
    root->i_mode = S_IFDIR | S_IRUSR | S_IWUSR;
    simple_inode_init_ts(root);
    s->s_root = d_make_root(root);
    if (!s->s_root)
        return -ENOMEM;
    s->s_d_op = ctx->dops;
    return 0;
}

/**
 * simple_inode_init_ts - initialize the timestamps for a new inode
 * @inode: inode to be initialized
 *
 * When a new inode is created, most filesystems set the timestamps to the
 * current time. Add a helper to do this.
 */
struct timespec64 simple_inode_init_ts(struct inode *inode)
{
#if 0
    struct timespec64 ts = inode_set_ctime_current(inode);

    inode_set_atime_to_ts(inode, ts);
    inode_set_mtime_to_ts(inode, ts);
    return ts;
#endif
    struct timespec64 ts;
    memset(&ts, 0, sizeof(ts));
    pr_notice("%s: No impl.", __func__);
    return ts;
}

static int pseudo_fs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, pseudo_fs_fill_super);
}

static void pseudo_fs_free(struct fs_context *fc)
{
    kfree(fc->fs_private);
}

static const struct fs_context_operations pseudo_fs_context_ops = {
    .free       = pseudo_fs_free,
    .get_tree   = pseudo_fs_get_tree,
};

/*
 * Common helper for pseudo-filesystems (sockfs, pipefs, bdev - stuff that
 * will never be mountable)
 */
struct pseudo_fs_context *init_pseudo(struct fs_context *fc,
                    unsigned long magic)
{
    struct pseudo_fs_context *ctx;

    ctx = kzalloc(sizeof(struct pseudo_fs_context), GFP_KERNEL);
    if (likely(ctx)) {
        ctx->magic = magic;
        fc->fs_private = ctx;
        fc->ops = &pseudo_fs_context_ops;
        fc->sb_flags |= SB_NOUSER;
        fc->global = true;
    }
    return ctx;
}

/**
 * generic_check_addressable - Check addressability of file system
 * @blocksize_bits: log of file system block size
 * @num_blocks:     number of blocks in file system
 *
 * Determine whether a file system with @num_blocks blocks (and a
 * block size of 2**@blocksize_bits) is addressable by the sector_t
 * and page cache of the system.  Return 0 if so and -EFBIG otherwise.
 */
int generic_check_addressable(unsigned blocksize_bits, u64 num_blocks)
{
    u64 last_fs_block = num_blocks - 1;
    u64 last_fs_page =
        last_fs_block >> (PAGE_SHIFT - blocksize_bits);

    if (unlikely(num_blocks == 0))
        return 0;

    if ((blocksize_bits < 9) || (blocksize_bits > PAGE_SHIFT))
        return -EINVAL;

    if ((last_fs_block > (sector_t)(~0ULL) >> (blocksize_bits - 9)) ||
        (last_fs_page > (pgoff_t)(~0ULL))) {
        return -EFBIG;
    }
    return 0;
}

/**
 * generic_set_sb_d_ops - helper for choosing the set of
 * filesystem-wide dentry operations for the enabled features
 * @sb: superblock to be configured
 *
 * Filesystems supporting casefolding and/or fscrypt can call this
 * helper at mount-time to configure sb->s_d_op to best set of dentry
 * operations required for the enabled features. The helper must be
 * called after these have been configured, but before the root dentry
 * is created.
 */
void generic_set_sb_d_ops(struct super_block *sb)
{
#if IS_ENABLED(CONFIG_UNICODE)
    if (sb->s_encoding) {
        sb->s_d_op = &generic_ci_dentry_ops;
        return;
    }
#endif
#ifdef CONFIG_FS_ENCRYPTION
    if (sb->s_cop) {
        sb->s_d_op = &generic_encrypted_dentry_ops;
        return;
    }
#endif
}

/**
 * inode_query_iversion - read i_version for later use
 * @inode: inode from which i_version should be read
 *
 * Read the inode i_version counter. This should be used by callers that wish
 * to store the returned i_version for later comparison. This will guarantee
 * that a later query of the i_version will result in a different value if
 * anything has changed.
 *
 * In this implementation, we fetch the current value, set the QUERIED flag and
 * then try to swap it into place with a cmpxchg, if it wasn't already set. If
 * that fails, we try again with the newly fetched value from the cmpxchg.
 */
u64 inode_query_iversion(struct inode *inode)
{
    u64 cur, new;
    bool fenced = false;

    /*
     * Memory barriers (implicit in cmpxchg, explicit in smp_mb) pair with
     * inode_maybe_inc_iversion(), see that routine for more details.
     */
    cur = inode_peek_iversion_raw(inode);
    do {
        /* If flag is already set, then no need to swap */
        if (cur & I_VERSION_QUERIED) {
            if (!fenced)
                smp_mb();
            break;
        }

        fenced = true;
        new = cur | I_VERSION_QUERIED;
    } while (!atomic64_try_cmpxchg(&inode->i_version, &cur, new));
    return cur >> I_VERSION_QUERIED_SHIFT;
}

/**
 * inode_maybe_inc_iversion - increments i_version
 * @inode: inode with the i_version that should be updated
 * @force: increment the counter even if it's not necessary?
 *
 * Every time the inode is modified, the i_version field must be seen to have
 * changed by any observer.
 *
 * If "force" is set or the QUERIED flag is set, then ensure that we increment
 * the value, and clear the queried flag.
 *
 * In the common case where neither is set, then we can return "false" without
 * updating i_version.
 *
 * If this function returns false, and no other metadata has changed, then we
 * can avoid logging the metadata.
 */
bool inode_maybe_inc_iversion(struct inode *inode, bool force)
{
    u64 cur, new;

    /*
     * The i_version field is not strictly ordered with any other inode
     * information, but the legacy inode_inc_iversion code used a spinlock
     * to serialize increments.
     *
     * We add a full memory barrier to ensure that any de facto ordering
     * with other state is preserved (either implicitly coming from cmpxchg
     * or explicitly from smp_mb if we don't know upfront if we will execute
     * the former).
     *
     * These barriers pair with inode_query_iversion().
     */
    cur = inode_peek_iversion_raw(inode);
    if (!force && !(cur & I_VERSION_QUERIED)) {
        smp_mb();
        cur = inode_peek_iversion_raw(inode);
    }

    do {
        /* If flag is clear then we needn't do anything */
        if (!force && !(cur & I_VERSION_QUERIED))
            return false;

        /* Since lowest bit is flag, add 2 to avoid it */
        new = (cur & ~I_VERSION_QUERIED) + I_VERSION_INCREMENT;
    } while (!atomic64_try_cmpxchg(&inode->i_version, &cur, new));
    return true;
}

/**
 * simple_setattr - setattr for simple filesystem
 * @idmap: idmap of the target mount
 * @dentry: dentry
 * @iattr: iattr structure
 *
 * Returns 0 on success, -error on failure.
 *
 * simple_setattr is a simple ->setattr implementation without a proper
 * implementation of size changes.
 *
 * It can either be used for in-memory filesystems or special files
 * on simple regular filesystems.  Anything that needs to change on-disk
 * or wire state on size changes needs its own setattr method.
 */
int simple_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
           struct iattr *iattr)
{
    struct inode *inode = d_inode(dentry);
    int error;

    error = setattr_prepare(idmap, dentry, iattr);
    if (error)
        return error;

    if (iattr->ia_valid & ATTR_SIZE)
        truncate_setsize(inode, iattr->ia_size);
    setattr_copy(idmap, inode, iattr);
    mark_inode_dirty(inode);
    return 0;
}
