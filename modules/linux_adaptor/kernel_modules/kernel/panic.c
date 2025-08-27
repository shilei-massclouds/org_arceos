#include <linux/debug_locks.h>
#include <linux/sched/debug.h>
#include <linux/interrupt.h>
#include <linux/kgdb.h>
#include <linux/kmsg_dump.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/vt_kern.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/ftrace.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/kexec.h>
#include <linux/panic_notifier.h>
#include <linux/sched.h>
#include <linux/string_helpers.h>
#include <linux/sysrq.h>
#include <linux/init.h>
#include <linux/nmi.h>
#include <linux/console.h>
#include <linux/bug.h>
#include <linux/ratelimit.h>
#include <linux/debugfs.h>
#include <linux/sysfs.h>
#include <linux/context_tracking.h>
#include <linux/seq_buf.h>
#include <trace/events/error_report.h>
#include <asm/sections.h>

extern int _vprintk(const char *fmt, va_list args);

atomic_t panic_cpu = ATOMIC_INIT(PANIC_CPU_INVALID);

void __warn_printk(const char *fmt, ...)
{
    //bool rcu = warn_rcu_enter();
    va_list args;

    pr_warn(CUT_HERE);

    va_start(args, fmt);
    _vprintk(fmt, args);
    va_end(args);
    //warn_rcu_exit(rcu);
}

/**
 * print_tainted - return a string to represent the kernel taint state.
 *
 * For individual taint flag meanings, see Documentation/admin-guide/sysctl/kernel.rst
 *
 * The string is overwritten by the next call to print_tainted(),
 * but is always NULL terminated.
 */
const char *print_tainted(void)
{
    //return _print_tainted(false);
    return "[No impl.]";
}
