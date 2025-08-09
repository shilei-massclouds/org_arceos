#include <linux/export.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
#include "internal.h"

/*
 * Replace the fs->{rootmnt,root} with {mnt,dentry}. Put the old values.
 * It can block.
 */
void set_fs_root(struct fs_struct *fs, const struct path *path)
{
    struct path old_root;

    path_get(path);
    spin_lock(&fs->lock);
    write_seqcount_begin(&fs->seq);
    old_root = fs->root;
    fs->root = *path;
    write_seqcount_end(&fs->seq);
    spin_unlock(&fs->lock);
    if (old_root.dentry)
        path_put(&old_root);
}

/*
 * Replace the fs->{pwdmnt,pwd} with {mnt,dentry}. Put the old values.
 * It can block.
 */
void set_fs_pwd(struct fs_struct *fs, const struct path *path)
{
    struct path old_pwd;

    path_get(path);
    spin_lock(&fs->lock);
    write_seqcount_begin(&fs->seq);
    old_pwd = fs->pwd;
    fs->pwd = *path;
    write_seqcount_end(&fs->seq);
    spin_unlock(&fs->lock);

    if (old_pwd.dentry)
        path_put(&old_pwd);
}

/* to be mentioned only in INIT_TASK */
struct fs_struct init_fs = {
    .users      = 1,
    .lock       = __SPIN_LOCK_UNLOCKED(init_fs.lock),
    .seq        = SEQCNT_SPINLOCK_ZERO(init_fs.seq, &init_fs.lock),
    .umask      = 0022,
};
