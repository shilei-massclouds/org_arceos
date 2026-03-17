/*
 * Unikernel test for linux block driver
 */

#include <linux/printk.h>
#include <linux/blkdev.h>

void cl_test_block(void)
{
    dev_t devt = 0;
    //lookup_bdev("/vda", &devt);
    int ret = early_lookup_bdev("/dev/vda", &devt);
    printk("Open block device '%lx' .. ret(%d)\n", devt, ret);
}
