#include <linux/fs.h>
#include "booter.h"

static struct file_system_type *file_systems;

static struct file_system_type **find_filesystem(const char *name, unsigned len)
{
    struct file_system_type **p;
    for (p = &file_systems; *p; p = &(*p)->next)
        if (strcmp((*p)->name, name) == 0 &&
            !(*p)->name[len])
            break;
    return p;
}

int register_filesystem(struct file_system_type * fs)
{
    struct file_system_type ** p;
    p = find_filesystem(fs->name, strlen(fs->name));
    if (*p) {
        booter_panic("fs already exist!");
    }

    *p = fs;
    printk("register fs [%s]\n", fs->name);
    return 0;
}
