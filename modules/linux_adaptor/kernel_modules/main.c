#include "booter.h"
#include "clinux.h"
#include <linux/string.h>
#include <linux/printk.h>

extern void cl_virtio_init();
extern void cl_virtio_mmio_init();
extern void cl_virtio_blk_init();

int clinux_init()
{
    sbi_puts("cLinux base is starting ...\n");

    cl_virtio_init();
    cl_virtio_mmio_init();
    cl_virtio_blk_init();

    /* Test for reading block */
    char buf[16];
    /*
    memset(buf, 0, sizeof(buf));
    cl_read_block(0, buf, sizeof(buf));
    printk("\n=============\n");
    printk("Read Block: %x, %x, %x, %x\n",
           buf[0], buf[1], buf[2], buf[3]);
    printk("=============\n\n");
    */

    /* Test for writing block */
    char wbuf[] = {0xaa, 0xab, 0xac, 0xad};
    cl_write_block(2, wbuf, sizeof(wbuf));

    /* Test for reading block again after writing. */
    memset(buf, 0, sizeof(buf));
    cl_read_block(2, buf, sizeof(buf));
    printk("\n=============\n");
    printk("Read Block Again: %x, %x, %x, %x\n",
           buf[0], buf[1], buf[2], buf[3]);
    printk("=============\n\n");

    booter_panic("Reach here!\n");
    return 0;
}
