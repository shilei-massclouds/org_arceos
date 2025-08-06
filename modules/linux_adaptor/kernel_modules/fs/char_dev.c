#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/seq_file.h>

#include <linux/kobject.h>
#include <linux/kobj_map.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/backing-dev.h>
#include <linux/tty.h>

#include "internal.h"

void cd_forget(struct inode *inode)
{
#if 0
    spin_lock(&cdev_lock);
    list_del_init(&inode->i_devices);
    inode->i_cdev = NULL;
    inode->i_mapping = &inode->i_data;
    spin_unlock(&cdev_lock);
#endif
    pr_err("%s: No impl.", __func__);
}
