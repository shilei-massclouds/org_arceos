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

static int pseudo_fs_fill_super(struct super_block *s, struct fs_context *fc)
{
    PANIC("");
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
