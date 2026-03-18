/*
 * Unikernel test for linux block driver
 */

#include <linux/printk.h>
#include <linux/blkdev.h>

#include "adaptor.h"

#define BUF_SIZE PAGE_SIZE

static void test_read(dev_t devt)
{
    char *buf;
    struct file *fp;
    loff_t pos = 0;

    fp = bdev_file_open_by_dev(devt, BLK_OPEN_READ, NULL, NULL);
    if (IS_ERR(fp)) {
        PANIC("failed to open block device");
    }
    printk("Open block device for read ok!\n");

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
}

static void test_write(dev_t devt)
{
    char *buf;
    struct file *fp;
    loff_t pos = 0;

    fp = bdev_file_open_by_dev(devt, BLK_OPEN_WRITE, NULL, NULL);
    if (IS_ERR(fp)) {
        PANIC("failed to open block device");
    }
    printk("Open block device for write ok!\n");

    buf = alloc_pages_exact(BUF_SIZE, GFP_KERNEL);
    if (!buf) {
        PANIC("failed to alloc buffer");
    }
    memset(buf, 'A', BUF_SIZE);

    if (kernel_write(fp, buf, BUF_SIZE, &pos) <= 0) {
        PANIC("failed to write block device");
    }

    free_pages_exact(buf, BUF_SIZE);

    if (sync_file_range(fp, 0, 16, SYNC_FILE_RANGE_WRITE_AND_WAIT)) {
        PANIC("failed to sync block device");
    }

    bdev_fput(fp);
}

void cl_test_block(void)
{
    dev_t devt = 0;
    char dname[] = "/dev/vda";

    if (early_lookup_bdev(dname, &devt)) {
        PANIC("No block device!");
    }

    test_read(devt);
    test_write(devt);
    test_read(devt);
}
