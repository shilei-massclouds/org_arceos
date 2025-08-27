#include <linux/kobject.h>
#include <linux/slab.h>

#include "booter.h"
#include "fs/proc/internal.h"

struct proc_dir_entry *proc_mkdir(const char *name,
        struct proc_dir_entry *parent)
{
    log_debug("%s: No impl.", __func__);
    return kmalloc(sizeof(struct proc_dir_entry), 0);
}

struct proc_dir_entry *proc_create_data(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        const struct proc_ops *proc_ops, void *data)
{
    log_debug("%s: No impl.", __func__);
    return kmalloc(sizeof(struct proc_dir_entry), 0);
}

struct proc_dir_entry *proc_create_seq_private(const char *name, umode_t mode,
        struct proc_dir_entry *parent, const struct seq_operations *ops,
        unsigned int state_size, void *data)
{
    log_debug("%s: No impl.", __func__);
    return kmalloc(sizeof(struct proc_dir_entry), 0);
}
