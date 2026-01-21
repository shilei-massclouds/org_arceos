#include <linux/init.h>
#include <linux/printk.h>

#include "adaptor.h"

extern void legacy_puts(const char *str);

void cl_init(unsigned long hartid, unsigned long dtb_pa)
{
    int i = 3;
    unsigned long addr = 0x8000;
    legacy_puts("cl_init ..\n");
    //printk("[%d]: \n", i);
    printk("[%s]: cl_init .. i(%d) addr(%lx)\n", __func__, i, addr);
    RAW_PANIC("Reach here!\n");
    //setup_arch(NULL /* cmdline_p */);
}
