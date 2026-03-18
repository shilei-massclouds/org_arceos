/*
 * Unikernel test for linux block driver
 */

#include <linux/printk.h>
#include <linux/blkdev.h>

#include "adaptor.h"

#define BUF_SIZE PAGE_SIZE

void cl_test_block(void)
{
#if 0
    struct buffer_head *bh;
    struct block_device *bdev;
    struct file *bdev_file;
    int hblock, blocksize;
    ext4_fsblk_t sb_block;
    unsigned long offset;
    struct ext4_super_block *es;
    int errno;
#endif
    char *buf;
    struct file *fp;
    loff_t pos;
    dev_t devt = 0;
    char dname[] = "/dev/vda";

    if (early_lookup_bdev(dname, &devt)) {
        PANIC("No block device!");
    }

    fp = bdev_file_open_by_dev(devt, BLK_OPEN_READ, NULL, NULL);
    if (IS_ERR(fp)) {
        PANIC("failed to open block device");
    }
    printk("Open block device ok!\n");

    buf = alloc_pages_exact(BUF_SIZE, GFP_KERNEL);
    if (!buf) {
        PANIC("failed to alloc buffer");
    }

    if (kernel_read(fp, buf, BUF_SIZE, &pos) <= 0) {
        PANIC("failed to read block device");
    }
    printk("read: (%lx)\n", *((unsigned long *) buf));

    free_pages_exact(buf, BUF_SIZE);
    bdev_fput(fp);
#if 0
    struct block_device *dev;
    int ret = early_lookup_bdev("/dev/vda", &devt);

    dev = blkdev_get_no_open(devt);
    printk("Open block device '%lx' .. ret(%d) dev(%lx)\n", devt, ret, dev);
#endif
}
