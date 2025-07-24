#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs_parser.h>

#include "../adaptor.h"

/*
 * Handling of filesystem drivers list.
 * Rules:
 *  Inclusion to/removals from/scanning of list are protected by spinlock.
 *  During the unload module must call unregister_filesystem().
 *  We can access the fields of list element if:
 *      1) spinlock is held or
 *      2) we hold the reference to the module.
 *  The latter can be guaranteed by call of try_module_get(); if it
 *  returned 0 we must skip the element, otherwise we got the reference.
 *  Once the reference is obtained we can drop the spinlock.
 */

static struct file_system_type *file_systems;
static DEFINE_RWLOCK(file_systems_lock);

/* WARNING: This can be used only if we _already_ own a reference */
struct file_system_type *get_filesystem(struct file_system_type *fs)
{
    __module_get(fs->owner);
    return fs;
}

void put_filesystem(struct file_system_type *fs)
{
    module_put(fs->owner);
}

static struct file_system_type **find_filesystem(const char *name, unsigned len)
{
    struct file_system_type **p;
    for (p = &file_systems; *p; p = &(*p)->next)
        if (strncmp((*p)->name, name, len) == 0 &&
            !(*p)->name[len])
            break;
    return p;
}

/**
 *  register_filesystem - register a new filesystem
 *  @fs: the file system structure
 *
 *  Adds the file system passed to the list of file systems the kernel
 *  is aware of for mount and other syscalls. Returns 0 on success,
 *  or a negative errno code on an error.
 *
 *  The &struct file_system_type that is passed is linked into the kernel
 *  structures and must not be freed until the file system has been
 *  unregistered.
 */
int register_filesystem(struct file_system_type * fs)
{
    int res = 0;
    struct file_system_type ** p;

    if (fs->parameters &&
        !fs_validate_description(fs->name, fs->parameters))
        return -EINVAL;

    BUG_ON(strchr(fs->name, '.'));
    if (fs->next)
        return -EBUSY;
    write_lock(&file_systems_lock);
    p = find_filesystem(fs->name, strlen(fs->name));
    if (*p)
        res = -EBUSY;
    else
        *p = fs;
    write_unlock(&file_systems_lock);
    return res;
}
