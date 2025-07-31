#include <linux/cache.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/mount.h>
#include <linux/init.h>
#include <linux/idr.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>

#include "internal.h"

struct proc_dir_entry *proc_mkdir(const char *name,
        struct proc_dir_entry *parent)
{
    pr_err("%s: No impl.", __func__);
    return kmalloc(sizeof(struct proc_dir_entry), 0);
}

struct proc_dir_entry *proc_create_data(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        const struct proc_ops *proc_ops, void *data)
{
    pr_err("%s: No impl.", __func__);
    return kmalloc(sizeof(struct proc_dir_entry), 0);
}

struct proc_dir_entry *proc_create_single_data(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        int (*show)(struct seq_file *, void *), void *data)
{
    pr_err("%s: No impl.", __func__);
    return kmalloc(sizeof(struct proc_dir_entry), 0);
}

struct proc_dir_entry *proc_create_seq_private(const char *name, umode_t mode,
        struct proc_dir_entry *parent, const struct seq_operations *ops,
        unsigned int state_size, void *data)
{
    pr_err("%s: No impl.", __func__);
    return kmalloc(sizeof(struct proc_dir_entry), 0);
}
