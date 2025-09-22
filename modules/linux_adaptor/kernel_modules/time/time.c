#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/timex.h>
#include <linux/capability.h>
#include <linux/timekeeper_internal.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/math64.h>
#include <linux/ptrace.h>

#include <linux/uaccess.h>
#include <linux/compat.h>
#include <asm/unistd.h>

#include <generated/timeconst.h>
#include "timekeeping.h"

/**
 * jiffies_to_msecs - Convert jiffies to milliseconds
 * @j: jiffies value
 *
 * Avoid unnecessary multiplications/divisions in the
 * two most common HZ cases.
 *
 * Return: milliseconds value
 */
unsigned int jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
    return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
    return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
# if BITS_PER_LONG == 32
    return (HZ_TO_MSEC_MUL32 * j + (1ULL << HZ_TO_MSEC_SHR32) - 1) >>
           HZ_TO_MSEC_SHR32;
# else
    return DIV_ROUND_UP(j * HZ_TO_MSEC_NUM, HZ_TO_MSEC_DEN);
# endif
#endif
}
