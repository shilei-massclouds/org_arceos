#include "booter.h"

extern void cl_virtio_init();
extern void cl_virtio_mmio_init();
extern void cl_virtio_blk_init();

int clinux_init()
{
    sbi_puts("cLinux base is starting ...\n");

    cl_virtio_init();
    cl_virtio_mmio_init();
    cl_virtio_blk_init();

    booter_panic("Reach here!\n");
    return 0;
}
