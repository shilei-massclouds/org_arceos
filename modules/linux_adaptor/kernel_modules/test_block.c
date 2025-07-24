#include <linux/blkdev.h>

#include "adaptor.h"

void test_block(void)
{
    struct block_device *dev;
    dev = blkdev_get_no_open(MKDEV(0xFE, 0x00));
    if (dev == NULL) {
        PANIC("No block device!");
    }
    PANIC("Test block ok!");
}
