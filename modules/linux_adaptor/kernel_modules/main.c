#include "booter.h"

int clinux_init()
{
    sbi_puts("cLinux base is starting ...\n");
    booter_panic("Reach here!\n");
    return 0;
}
