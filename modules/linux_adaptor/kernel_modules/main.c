#include "booter.h"
#include <linux/string.h>

extern void cl_virtio_init();
extern void cl_virtio_mmio_init();
extern void cl_virtio_blk_init();

extern int cl_read_block(int blk_nr, void *rbuf, int count);

int clinux_init()
{
    sbi_puts("cLinux base is starting ...\n");

    cl_virtio_init();
    //cl_virtio_mmio_init();
    cl_virtio_blk_init();

    /* Test for reading block */
    /*
    char buf[16];
    memset(buf, 0, sizeof(buf));
    cl_read_block(0, buf, sizeof(buf));
    */
    booter_panic("Reach here!\n");
    return 0;
}
