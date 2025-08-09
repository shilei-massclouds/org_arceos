#include <linux/fs_context.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>

#include "fs/mount.h"
#include "fs/internal.h"

#include "adaptor.h"

int cl_mount(const char *fstype, const char *source)
{
    struct fs_context *fc;
    struct file_system_type *type;
    int err = 0;

    type = get_fs_type(fstype);
    if (type == NULL) {
        PANIC("No filesystem type.");
    }

    fc = fs_context_for_mount(type, SB_SILENT);
    put_filesystem(type);
    if (IS_ERR(fc)) {
        PANIC("Bad fs context.");
    }

    if (source) {
        err = vfs_parse_fs_string(fc, "source", source, strlen(source));
        if (err) {
            PANIC("Bad fs context params 'source'.");
        }
    }

    err = vfs_get_tree(fc);
    if (err || fc->root == NULL) {
        PANIC("get tree error.");
    }
    printk("%s: Mount filesystem on block ok!\n", __func__);

    /* Note: check why we need it? */
    up_write(&fc->root->d_sb->s_umount);

    struct vfsmount *mnt = vfs_create_mount(fc);
    if (IS_ERR(mnt)) {
        PANIC("create vfs mount error.");
    }

    struct path root;

    root.mnt = mnt;
    root.dentry = mnt->mnt_root;
    mnt->mnt_flags |= MNT_LOCKED;

    set_fs_pwd(current->fs, &root);
    set_fs_root(current->fs, &root);

    put_fs_context(fc);
    return 0;
}
