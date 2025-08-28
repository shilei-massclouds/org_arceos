#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/nmi.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/security.h>
#include <linux/memblock.h>
#include <linux/syscalls.h>
#include <linux/syscore_ops.h>
#include <linux/vmcore_info.h>
#include <linux/ratelimit.h>
#include <linux/kmsg_dump.h>
#include <linux/syslog.h>
#include <linux/cpu.h>
#include <linux/rculist.h>
#include <linux/poll.h>
#include <linux/irq_work.h>
#include <linux/ctype.h>
#include <linux/uio.h>
#include <linux/sched/clock.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>

#include <linux/uaccess.h>
#include <asm/sections.h>

#include <trace/events/initcall.h>
#define CREATE_TRACE_POINTS
#include <trace/events/printk.h>

#include "printk_ringbuffer.h"
#include "console_cmdline.h"
#include "braille.h"
#include "internal.h"

#include "../adaptor.h"

/*
 * Low level drivers may need that to know if they can schedule in
 * their unblank() callback or not. So let's export it.
 */
int oops_in_progress;

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

/* Return true if a panic is in progress on the current CPU. */
bool this_cpu_in_panic(void)
{
    /*
     * We can use raw_smp_processor_id() here because it is impossible for
     * the task to be migrated to the panic_cpu, or away from it. If
     * panic_cpu has already been set, and we're not currently executing on
     * that CPU, then we never will be.
     */
    return unlikely(atomic_read(&panic_cpu) == raw_smp_processor_id());
}

/**
 * __printk_cpu_sync_try_get() - Try to acquire the printk cpu-reentrant
 *                               spinning lock.
 *
 * If no processor has the lock, the calling processor takes the lock and
 * becomes the owner. If the calling processor is already the owner of the
 * lock, this function succeeds immediately.
 *
 * Context: Any context. Expects interrupts to be disabled.
 * Return: 1 on success, otherwise 0.
 */
int __printk_cpu_sync_try_get(void)
{
    pr_notice("%s: No impl.", __func__);
    return 1;
}

/**
 * __printk_cpu_sync_wait() - Busy wait until the printk cpu-reentrant
 *                            spinning lock is not owned by any CPU.
 *
 * Context: Any context.
 */
void __printk_cpu_sync_wait(void)
{
#if 0
    do {
        cpu_relax();
    } while (atomic_read(&printk_cpu_sync_owner) != -1);
#endif
    pr_notice("%s: No impl.", __func__);
}

/**
 * __printk_cpu_sync_put() - Release the printk cpu-reentrant spinning lock.
 *
 * The calling processor must be the owner of the lock.
 *
 * Context: Any context. Expects interrupts to be disabled.
 */
void __printk_cpu_sync_put(void)
{
    pr_notice("%s: No impl.", __func__);
}
