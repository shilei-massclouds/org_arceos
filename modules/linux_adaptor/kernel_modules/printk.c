#include <stdarg.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include "booter.h"

const char hex_asc[] = "0123456789abcdef";
const char hex_asc_upper[] = "0123456789ABCDEF";

enum print_usage {
    PRINTK_USAGE = 0,
    DEBUG_USAGE,
    ERROR_USAGE,
};

static int cl_vprintk(enum print_usage usage, const char *fmt, va_list args)
{
    int n;
    char buf[512];
    char *msg;

    n = vscnprintf(buf, sizeof(buf), fmt, args);
    if (printk_get_level(buf)) {
        msg = buf + 2;
        n -= 2;
    } else {
        msg = buf;
    }

    switch (usage) {
    case PRINTK_USAGE:
        cl_printk(msg);
        break;
    case DEBUG_USAGE:
        cl_log_debug(msg);
        break;
    case ERROR_USAGE:
        cl_log_error(msg);
        break;
    default:
        cl_printk(msg);
    }
}

int printk(const char *fmt, ...)
{
    int ret;
    va_list args;
    va_start(args, fmt);
    ret = cl_vprintk(PRINTK_USAGE, printk_skip_level(fmt), args);
    va_end(args);
    return ret;
}

void __warn_printk(const char *fmt, ...)
{
    printk("[RAW_WARN_PRINTK]:\n");

    int ret;
    va_list args;
    va_start(args, fmt);
    ret = cl_vprintk(PRINTK_USAGE, printk_skip_level(fmt), args);
    va_end(args);
    return ret;
}

int log_debug(const char *fmt, ...)
{
    int ret;
    va_list args;
    va_start(args, fmt);
    ret = cl_vprintk(DEBUG_USAGE, printk_skip_level(fmt), args);
    va_end(args);
    return ret;
}

int log_error(const char *fmt, ...)
{
    int ret;
    va_list args;
    va_start(args, fmt);
    ret = cl_vprintk(ERROR_USAGE, printk_skip_level(fmt), args);
    va_end(args);
    return ret;
}

/**
 * skip_spaces - Removes leading whitespace from @str.
 * @str: The string to be stripped.
 *
 * Returns a pointer to the first non-whitespace character in @str.
 */
char *skip_spaces(const char *str)
{
    while (isspace(*str))
        ++str;
    return (char *)str;
}

void _dev_notice(const struct device *dev, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    cl_vprintk(PRINTK_USAGE, printk_skip_level(fmt), args);
    va_end(args);
}
