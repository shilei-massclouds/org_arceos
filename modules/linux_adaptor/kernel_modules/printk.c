#include <stdarg.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include "booter.h"

const char hex_asc[] = "0123456789abcdef";
const char hex_asc_upper[] = "0123456789ABCDEF";

int vprintk(const char *fmt, va_list args)
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
    sbi_puts(msg);
    //early_console->write(early_console, msg, n);
}

int printk(const char *fmt, ...)
{
    int ret;
    va_list args;
    va_start(args, fmt);
    ret = vprintk(printk_skip_level(fmt), args);
    va_end(args);
    return ret;
}

__weak void __warn_printk(const char *fmt, ...)
{
    sbi_puts("[RAW_WARN_PRINTK] ");
    sbi_puts(fmt);
    sbi_puts("\n");
    sbi_shutdown();
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
