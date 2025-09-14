#include <linux/module.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/fd.h>
#include <linux/tty.h>
#include <linux/suspend.h>
#include <linux/root_dev.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/async.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>
#include <linux/ramfs.h>
#include <linux/shmem_fs.h>
#include <linux/ktime.h>

#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include <linux/nfs_mount.h>
#include <linux/raid/detect.h>
#include <uapi/linux/mount.h>

#include "do_mounts.h"
#include "../adaptor.h"

static char __initdata saved_root_name[64];
static int root_wait;

dev_t ROOT_DEV;

static int __init root_dev_setup(char *line)
{
    strscpy(saved_root_name, line, sizeof(saved_root_name));
    return 0;
}

early_param("root", root_dev_setup);

static dev_t __init parse_root_device(char *root_device_name)
{
    int error;
    dev_t dev;

    if (!strncmp(root_device_name, "mtd", 3) ||
        !strncmp(root_device_name, "ubi", 3))
        return Root_Generic;
    if (strcmp(root_device_name, "/dev/nfs") == 0)
        return Root_NFS;
    if (strcmp(root_device_name, "/dev/cifs") == 0)
        return Root_CIFS;
    if (strcmp(root_device_name, "/dev/ram") == 0)
        return Root_RAM0;

    error = early_lookup_bdev(root_device_name, &dev);
    if (error) {
        if (error == -EINVAL && root_wait) {
            pr_err("Disabling rootwait; root= is invalid.\n");
            root_wait = 0;
        }
        return 0;
    }
    return dev;
}

/*
 * Prepare the namespace - decide what/where to mount, load ramdisks, etc.
 */
void __init prepare_namespace(void)
{
    if (saved_root_name[0])
        ROOT_DEV = parse_root_device(saved_root_name);
    printk("ROOT_DEV: %x\n", ROOT_DEV);
}
