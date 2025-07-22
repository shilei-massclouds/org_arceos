#include <linux/printk.h>
#include <linux/sprintf.h>

#include "../adaptor.h"

int _vprintk(const char *fmt, va_list args)
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

#define define_dev_printk_level(func, kern_level)       \
void func(const struct device *dev, const char *fmt, ...)   \
{                               \
    va_list args;               \
                                \
    va_start(args, fmt);        \
    _vprintk(fmt, args);        \
    va_end(args);               \
}                               \
EXPORT_SYMBOL(func);

define_dev_printk_level(_dev_emerg, KERN_EMERG);
define_dev_printk_level(_dev_alert, KERN_ALERT);
define_dev_printk_level(_dev_crit, KERN_CRIT);
define_dev_printk_level(_dev_err, KERN_ERR);
define_dev_printk_level(_dev_warn, KERN_WARNING);
define_dev_printk_level(_dev_notice, KERN_NOTICE);
define_dev_printk_level(_dev_info, KERN_INFO);
