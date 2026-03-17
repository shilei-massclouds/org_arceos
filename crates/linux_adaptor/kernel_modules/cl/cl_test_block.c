/*
 * Unikernel test for linux block driver
 */

#include <linux/printk.h>
#include <linux/blkdev.h>

void cl_test_block(void)
{
    dev_t devt;
    lookup_bdev("/dev/vda", &devt);

    printk("Open block device '%lx' ..\n", devt);
}
