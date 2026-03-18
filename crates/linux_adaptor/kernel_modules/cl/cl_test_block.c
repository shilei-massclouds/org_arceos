/*
 * Unikernel test for linux block driver
 */

#include <linux/blkdev.h>

#include "adaptor.h"

#define BLK_SIZE 1024

/* The initial magic of 'disk.img' created by ArceOS */
unsigned long init_magic = 0x2e73666b6d9058eb;
unsigned long test_magic = 0xa00afeedb00bfeed;

void cl_test_block(void)
{
    char *buf;
    dev_t devt = 0;
    char dname[] = "/dev/vda";

    if (early_lookup_bdev(dname, &devt)) {
        PANIC("No block device.");
    }

    buf = alloc_pages_exact(BLK_SIZE, GFP_KERNEL);
    if (!buf) {
        PANIC("failed to alloc buffer.");
    }

    /* Check the header magic of 'disk.img' */
    cl_read_block(devt, buf, BLK_SIZE, 0);
    if (memcmp(buf, &init_magic, sizeof(init_magic))) {
        printk("bad magic (%lx)\n", *((unsigned long *)buf));
        PANIC("verify the init magic err.");
    }

    /* Overwrite the magic */
    memcpy(buf, &test_magic, sizeof(test_magic));
    cl_write_block(devt, buf, BLK_SIZE, 0);

    /* Check the new magic */
    cl_read_block(devt, buf, BLK_SIZE, 0);
    if (memcmp(buf, &test_magic, sizeof(init_magic))) {
        printk("bad magic (%lx)\n", *((unsigned long *)buf));
        PANIC("verify the new magic err.");
    }

    /* Restore the old magic */
    memcpy(buf, &init_magic, sizeof(test_magic));
    cl_write_block(devt, buf, BLK_SIZE, 0);

    /* Makesure everything is fine */
    cl_read_block(devt, buf, BLK_SIZE, 0);
    if (memcmp(buf, &init_magic, sizeof(init_magic))) {
        printk("bad magic (%lx)\n", *((unsigned long *)buf));
        PANIC("verify the init magic err.");
    }

    free_pages_exact(buf, BLK_SIZE);
}
