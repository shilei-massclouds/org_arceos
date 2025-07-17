#include <linux/bug.h>

#include "../adaptor.h"

#ifdef CONFIG_BUG
void __warn_printk(const char *fmt, ...)
{
    int ret;
    va_list args;

    printk("WARN: ");
    va_start(args, fmt);
    ret = _vprintk(fmt, args);
    va_end(args);
}
#endif
