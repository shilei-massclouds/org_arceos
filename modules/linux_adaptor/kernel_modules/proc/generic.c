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
