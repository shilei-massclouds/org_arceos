#include <linux/device.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/backing-dev.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/blkpg.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/mtd/map.h>

#include <linux/uaccess.h>

#include "mtdcore.h"
#include "adaptor.h"

/*
 * Data structure to hold the pointer to the mtd device as well
 * as mode information of various use cases.
 */
struct mtd_file_info {
    struct mtd_info *mtd;
    enum mtd_file_modes mode;
};

static loff_t mtdchar_lseek(struct file *file, loff_t offset, int orig)
{
#if 0
    struct mtd_file_info *mfi = file->private_data;
    return fixed_size_llseek(file, offset, orig, mfi->mtd->size);
#endif
    PANIC("");
}

static int mtdchar_open(struct inode *inode, struct file *file)
{
    PANIC("");
}

static int mtdchar_close(struct inode *inode, struct file *file)
{
    PANIC("");
}

static ssize_t mtdchar_read(struct file *file, char __user *buf, size_t count,
            loff_t *ppos)
{
    PANIC("");
}

static ssize_t mtdchar_write(struct file *file, const char __user *buf, size_t count,
            loff_t *ppos)
{
    PANIC("");
}

static long mtdchar_unlocked_ioctl(struct file *file, u_int cmd, u_long arg)
{
    PANIC("");
}

/*
 * set up a mapping for shared memory segments
 */
static int mtdchar_mmap(struct file *file, struct vm_area_struct *vma)
{
    PANIC("");
}

static long mtdchar_compat_ioctl(struct file *file, unsigned int cmd,
    unsigned long arg)
{
    PANIC("");
}

static const struct file_operations mtd_fops = {
    .owner      = THIS_MODULE,
    .llseek     = mtdchar_lseek,
    .read       = mtdchar_read,
    .write      = mtdchar_write,
    .unlocked_ioctl = mtdchar_unlocked_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = mtdchar_compat_ioctl,
#endif
    .open       = mtdchar_open,
    .release    = mtdchar_close,
    .mmap       = mtdchar_mmap,
#ifndef CONFIG_MMU
    .get_unmapped_area = mtdchar_get_unmapped_area,
    .mmap_capabilities = mtdchar_mmap_capabilities,
#endif
};

int __init init_mtdchar(void)
{
    int ret;

    ret = __register_chrdev(MTD_CHAR_MAJOR, 0, 1 << MINORBITS,
                   "mtd", &mtd_fops);
    if (ret < 0) {
        pr_err("Can't allocate major number %d for MTD\n",
               MTD_CHAR_MAJOR);
        return ret;
    }

    return ret;
}
