#include <linux/init.h>
#include <linux/printk.h>

#include <asm/setup.h>
#include <linux/memblock.h>

#include "adaptor.h"

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

void cl_init(unsigned long hartid, unsigned long dtb_pa)
{
    //setup_arch(NULL /* cmdline_p */);
}
