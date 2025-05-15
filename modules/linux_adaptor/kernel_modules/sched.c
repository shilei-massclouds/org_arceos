#include <linux/printk.h>

#include "booter.h"

void __might_sleep(const char *file, int line, int preempt_offset)
{
    printk("%s: \n", __func__);
}
