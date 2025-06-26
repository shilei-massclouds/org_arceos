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
