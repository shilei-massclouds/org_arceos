#include <linux/printk.h>
#include <linux/sprintf.h>

#include "../adaptor.h"

static int _vprintk(const char *fmt, va_list args)
{
    int n;
    char buf[512];
    char *msg;
    int level;

    level = printk_get_level(fmt);
    n = vscnprintf(buf, sizeof(buf), printk_skip_level(fmt), args);
    cl_printk(level, buf);
    return n;
}

int _printk(const char *fmt, ...)
{
    int ret;
    va_list args;
    va_start(args, fmt);
    ret = _vprintk(fmt, args);
    va_end(args);
    return ret;
}
