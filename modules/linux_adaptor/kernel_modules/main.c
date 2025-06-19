#include "booter.h"
#include <linux/string.h>
#include <linux/printk.h>

extern int cl_irq_init(void);
extern int cl_enable_irq(void);

extern void cl_virtio_init();
extern void cl_virtio_mmio_init();
extern void cl_virtio_blk_init();

static int test_read_blocks();
static int test_write_blocks();
extern int clinux_test_block_driver(void);

int clinux_init()
{
    printk("cLinux base is starting ...\n");

    cl_irq_init();

    cl_virtio_init();
    cl_virtio_mmio_init();
    cl_virtio_blk_init();

    cl_enable_irq();

    clinux_test_block_driver();

    return 0;
}

int clinux_test_block_driver(void)
{
#if 0
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
    printk("after cl_read_block!\n");
    /*
    if (!buf[0] || !buf[1] || !buf[2] || !buf[3]) {
        booter_panic("Read block error!\n");
    }
    */

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
    return 0;
}

static int write_a_block(int blk_nr)
{
    read_a_block(blk_nr);
    read_a_block(blk_nr+1);

    char wbuf[512];
    memset(wbuf, 0xAB, sizeof(wbuf));
    cl_write_block(blk_nr, wbuf, sizeof(wbuf));

    read_a_block(blk_nr);
    read_a_block(blk_nr+1);
    return 0;
}

/* Test for writing block */
static int test_write_blocks()
{
    write_a_block(0);
    return 0;
}

__weak int cl_irq_init(void)
{
    printk("No impl for %s\n", __func__);
    return 0;
}

#include <linux/cpumask.h>

// Temporarily
void (*__smp_cross_call)(const struct cpumask *, unsigned int);

void __init set_smp_cross_call(void (*fn)(const struct cpumask *, unsigned int))
{
    __smp_cross_call = fn;
    printk("%s: ok\n", __func__);
}
