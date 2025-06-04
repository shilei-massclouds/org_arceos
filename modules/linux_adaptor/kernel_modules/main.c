#include "booter.h"
#include "clinux.h"
#include <linux/string.h>
#include <linux/printk.h>

extern void cl_virtio_init();
extern void cl_virtio_mmio_init();
extern void cl_virtio_blk_init();

static int test_read_blocks();
static int test_write_blocks();

int clinux_init()
{
    sbi_puts("cLinux base is starting ...\n");

    cl_virtio_init();
    cl_virtio_mmio_init();
    cl_virtio_blk_init();

#if 1
    test_read_blocks();
    booter_panic("Reach here!\n");
#endif

#if 0
    test_write_blocks();
    booter_panic("Reach here!\n");
#endif

    return 0;
}

/* Utilities for testing */
static int read_a_block(int blk_nr)
{
    char buf[16];
    memset(buf, 0, sizeof(buf));
    cl_read_block(blk_nr, buf, sizeof(buf));
    if (!buf[0] || !buf[1] || !buf[2] || !buf[3]) {
        booter_panic("Read block error!\n");
    }

    printk("\n=============\n");
    printk("Read Block[%d]: %x, %x, %x, %x\n",
           blk_nr, buf[0], buf[1], buf[2], buf[3]);
    printk("=============\n\n");
    return 0;
}

/* Test for reading block */
static int test_read_blocks()
{
    read_a_block(0);
    read_a_block(1);
}

/* Test for writing block */
static int test_write_blocks()
{
    read_a_block(0);

    char wbuf[] = {0xaa, 0xab, 0xac, 0xad};
    cl_write_block(0, wbuf, sizeof(wbuf));

    read_a_block(0);
}
