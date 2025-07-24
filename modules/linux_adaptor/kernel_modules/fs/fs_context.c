#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include <linux/security.h>
#include <linux/mnt_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>
#include <asm/sections.h>
#include "mount.h"
#include "internal.h"

#include "../adaptor.h"

static char *vfs_parse_comma_sep(char **s)
{
    return strsep(s, ",");
}

/*
 * Initialise a legacy context for a filesystem that doesn't support
 * fs_context.
 */
static int legacy_init_fs_context(struct fs_context *fc)
{
#if 0
    fc->fs_private = kzalloc(sizeof(struct legacy_fs_context), GFP_KERNEL_ACCOUNT);
    if (!fc->fs_private)
        return -ENOMEM;
    fc->ops = &legacy_fs_context_ops;
    return 0;
#endif
    PANIC("");
}

/**
 * alloc_fs_context - Create a filesystem context.
 * @fs_type: The filesystem type.
 * @reference: The dentry from which this one derives (or NULL)
 * @sb_flags: Filesystem/superblock flags (SB_*)
 * @sb_flags_mask: Applicable members of @sb_flags
 * @purpose: The purpose that this configuration shall be used for.
 *
 * Open a filesystem and create a mount context.  The mount context is
 * initialised with the supplied flags and, if a submount/automount from
 * another superblock (referred to by @reference) is supplied, may have
 * parameters such as namespaces copied across from that superblock.
 */
static struct fs_context *alloc_fs_context(struct file_system_type *fs_type,
                      struct dentry *reference,
                      unsigned int sb_flags,
                      unsigned int sb_flags_mask,
                      enum fs_context_purpose purpose)
{
    int (*init_fs_context)(struct fs_context *);
    struct fs_context *fc;
    int ret = -ENOMEM;

    fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL_ACCOUNT);
    if (!fc)
        return ERR_PTR(-ENOMEM);

    fc->purpose = purpose;
    fc->sb_flags    = sb_flags;
    fc->sb_flags_mask = sb_flags_mask;
    fc->fs_type = get_filesystem(fs_type);
    fc->cred    = get_current_cred();
    fc->net_ns  = get_net(current->nsproxy->net_ns);
    fc->log.prefix  = fs_type->name;

    mutex_init(&fc->uapi_mutex);

    switch (purpose) {
    case FS_CONTEXT_FOR_MOUNT:
        pr_err("%s: No user_ns.", __func__);
        //fc->user_ns = get_user_ns(fc->cred->user_ns);
        break;
    case FS_CONTEXT_FOR_SUBMOUNT:
        fc->user_ns = get_user_ns(reference->d_sb->s_user_ns);
        break;
    case FS_CONTEXT_FOR_RECONFIGURE:
        atomic_inc(&reference->d_sb->s_active);
        fc->user_ns = get_user_ns(reference->d_sb->s_user_ns);
        fc->root = dget(reference);
        break;
    }

    /* TODO: Make all filesystems support this unconditionally */
    init_fs_context = fc->fs_type->init_fs_context;
    if (!init_fs_context)
        init_fs_context = legacy_init_fs_context;

    ret = init_fs_context(fc);
    if (ret < 0)
        goto err_fc;
    fc->need_free = true;
    return fc;

err_fc:
    PANIC("ERR!");
    put_fs_context(fc);
    return ERR_PTR(ret);
}

struct fs_context *fs_context_for_mount(struct file_system_type *fs_type,
                    unsigned int sb_flags)
{
    return alloc_fs_context(fs_type, NULL, sb_flags, 0,
                    FS_CONTEXT_FOR_MOUNT);
}

/*
 * Free a logging structure.
 */
static void put_fc_log(struct fs_context *fc)
{
    struct fc_log *log = fc->log.log;
    int i;

    if (log) {
        if (refcount_dec_and_test(&log->usage)) {
            fc->log.log = NULL;
            for (i = 0; i <= 7; i++)
                if (log->need_free & (1 << i))
                    kfree(log->buffer[i]);
            kfree(log);
        }
    }
}

/**
 * put_fs_context - Dispose of a superblock configuration context.
 * @fc: The context to dispose of.
 */
void put_fs_context(struct fs_context *fc)
{
    struct super_block *sb;

    if (fc->root) {
        sb = fc->root->d_sb;
        dput(fc->root);
        fc->root = NULL;
        deactivate_super(sb);
    }

    if (fc->need_free && fc->ops && fc->ops->free)
        fc->ops->free(fc);

    pr_err("%s: No impl.", __func__);
#if 0
    security_free_mnt_opts(&fc->security);
    put_net(fc->net_ns);
    put_user_ns(fc->user_ns);
    put_cred(fc->cred);
#endif
    put_fc_log(fc);
    put_filesystem(fc->fs_type);
    kfree(fc->source);
    kfree(fc);
}

/**
 * vfs_parse_fs_string - Convenience function to just parse a string.
 * @fc: Filesystem context.
 * @key: Parameter name.
 * @value: Default value.
 * @v_size: Maximum number of bytes in the value.
 */
int vfs_parse_fs_string(struct fs_context *fc, const char *key,
            const char *value, size_t v_size)
{
    int ret;

    struct fs_parameter param = {
        .key    = key,
        .type   = fs_value_is_flag,
        .size   = v_size,
    };

    if (value) {
        param.string = kmemdup_nul(value, v_size, GFP_KERNEL);
        if (!param.string)
            return -ENOMEM;
        param.type = fs_value_is_string;
    }

    ret = vfs_parse_fs_param(fc, &param);
    kfree(param.string);
    return ret;
}

/**
 * vfs_parse_fs_param - Add a single parameter to a superblock config
 * @fc: The filesystem context to modify
 * @param: The parameter
 *
 * A single mount option in string form is applied to the filesystem context
 * being set up.  Certain standard options (for example "ro") are translated
 * into flag bits without going to the filesystem.  The active security module
 * is allowed to observe and poach options.  Any other options are passed over
 * to the filesystem to parse.
 *
 * This may be called multiple times for a context.
 *
 * Returns 0 on success and a negative error code on failure.  In the event of
 * failure, supplementary error information may have been set.
 */
int vfs_parse_fs_param(struct fs_context *fc, struct fs_parameter *param)
{
    int ret;

    if (!param->key)
        return invalf(fc, "Unnamed parameter\n");

#if 0
    ret = vfs_parse_sb_flag(fc, param->key);
    if (ret != -ENOPARAM)
        return ret;

    ret = security_fs_context_parse_param(fc, param);
    if (ret != -ENOPARAM)
        /* Param belongs to the LSM or is disallowed by the LSM; so
         * don't pass to the FS.
         */
        return ret;
#endif

    if (fc->ops->parse_param) {
        ret = fc->ops->parse_param(fc, param);
        if (ret != -ENOPARAM)
            return ret;
    }

    /* If the filesystem doesn't take any arguments, give it the
     * default handling of source.
     */
    ret = vfs_parse_fs_param_source(fc, param);
    if (ret != -ENOPARAM)
        return ret;

    return invalf(fc, "%s: Unknown parameter '%s'",
              fc->fs_type->name, param->key);
}

/**
 * vfs_parse_fs_param_source - Handle setting "source" via parameter
 * @fc: The filesystem context to modify
 * @param: The parameter
 *
 * This is a simple helper for filesystems to verify that the "source" they
 * accept is sane.
 *
 * Returns 0 on success, -ENOPARAM if this is not  "source" parameter, and
 * -EINVAL otherwise. In the event of failure, supplementary error information
 *  is logged.
 */
int vfs_parse_fs_param_source(struct fs_context *fc, struct fs_parameter *param)
{
    if (strcmp(param->key, "source") != 0)
        return -ENOPARAM;

    if (param->type != fs_value_is_string)
        return invalf(fc, "Non-string source");

    if (fc->source)
        return invalf(fc, "Multiple sources");

    fc->source = param->string;
    param->string = NULL;
    return 0;
}

/**
 * logfc - Log a message to a filesystem context
 * @log: The filesystem context to log to, or NULL to use printk.
 * @prefix: A string to prefix the output with, or NULL.
 * @level: 'w' for a warning, 'e' for an error.  Anything else is a notice.
 * @fmt: The format of the buffer.
 */
void logfc(struct fc_log *log, const char *prefix, char level, const char *fmt, ...)
{
    PANIC("");
}

int parse_monolithic_mount_data(struct fs_context *fc, void *data)
{
    int (*monolithic_mount_data)(struct fs_context *, void *);

    monolithic_mount_data = fc->ops->parse_monolithic;
    if (!monolithic_mount_data)
        monolithic_mount_data = generic_parse_monolithic;

    return monolithic_mount_data(fc, data);
}

/**
 * generic_parse_monolithic - Parse key[=val][,key[=val]]* mount data
 * @fc: The superblock configuration to fill in.
 * @data: The data to parse
 *
 * Parse a blob of data that's in key[=val][,key[=val]]* form.  This can be
 * called from the ->monolithic_mount_data() fs_context operation.
 *
 * Returns 0 on success or the error returned by the ->parse_option() fs_context
 * operation on failure.
 */
int generic_parse_monolithic(struct fs_context *fc, void *data)
{
    return vfs_parse_monolithic_sep(fc, data, vfs_parse_comma_sep);
}

/**
 * vfs_parse_monolithic_sep - Parse key[=val][,key[=val]]* mount data
 * @fc: The superblock configuration to fill in.
 * @data: The data to parse
 * @sep: callback for separating next option
 *
 * Parse a blob of data that's in key[=val][,key[=val]]* form with a custom
 * option separator callback.
 *
 * Returns 0 on success or the error returned by the ->parse_option() fs_context
 * operation on failure.
 */
int vfs_parse_monolithic_sep(struct fs_context *fc, void *data,
                 char *(*sep)(char **))
{
    char *options = data, *key;
    int ret = 0;

    if (!options)
        return 0;

#if 0
    ret = security_sb_eat_lsm_opts(options, &fc->security);
    if (ret)
        return ret;
#endif

    while ((key = sep(&options)) != NULL) {
        if (*key) {
            size_t v_len = 0;
            char *value = strchr(key, '=');

            if (value) {
                if (value == key)
                    continue;
                *value++ = 0;
                v_len = strlen(value);
            }
            ret = vfs_parse_fs_string(fc, key, value, v_len);
            if (ret < 0)
                break;
        }
    }

    return ret;
}
