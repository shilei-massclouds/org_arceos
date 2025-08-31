#include <linux/kernel.h>
#include <linux/buildid.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <linux/kexec.h>
#include <linux/utsname.h>
#include <linux/stop_machine.h>

#include "../adaptor.h"

#if IS_ENABLED(CONFIG_STACKTRACE_BUILD_ID)
#define BUILD_ID_FMT " %20phN"
#define BUILD_ID_VAL vmlinux_build_id
#else
#define BUILD_ID_FMT "%s"
#define BUILD_ID_VAL ""
#endif

/**
 * dump_stack_print_info - print generic debug info for dump_stack()
 * @log_lvl: log level
 *
 * Arch-specific dump_stack() implementations can use this function to
 * print out the same debug information as the generic dump_stack().
 */
void dump_stack_print_info(const char *log_lvl)
{
    printk("\n%sCPU: %d UID: %u PID: %d Comm: %.20s " BUILD_ID_FMT "\n",
           log_lvl, raw_smp_processor_id(),
           __kuid_val(current_real_cred()->euid),
           current->pid, current->comm,
           kexec_crash_loaded() ? "Kdump: loaded " : "",
           BUILD_ID_VAL);

#if 0
    if (get_taint())
        printk("%s%s\n", log_lvl, print_tainted_verbose());

    if (dump_stack_arch_desc_str[0] != '\0')
        printk("%sHardware name: %s\n",
               log_lvl, dump_stack_arch_desc_str);

    print_worker_info(log_lvl, current);
    print_stop_info(log_lvl, current);
    print_scx_info(log_lvl, current);
#endif
}

static void __dump_stack(const char *log_lvl)
{
    dump_stack_print_info(log_lvl);
    show_stack(NULL, NULL, log_lvl);
}

/**
 * dump_stack_lvl - dump the current task information and its stack trace
 * @log_lvl: log level
 *
 * Architectures can override this implementation by implementing its own.
 */
asmlinkage __visible void dump_stack_lvl(const char *log_lvl)
{
    bool in_panic = this_cpu_in_panic();
    unsigned long flags;

    /*
     * Permit this cpu to perform nested stack dumps while serialising
     * against other CPUs, unless this CPU is in panic.
     *
     * When in panic, non-panic CPUs are not permitted to store new
     * printk messages so there is no need to synchronize the output.
     * This avoids potential deadlock in panic() if another CPU is
     * holding and unable to release the printk_cpu_sync.
     */
    if (!in_panic)
        printk_cpu_sync_get_irqsave(flags);

    __dump_stack(log_lvl);

    if (!in_panic)
        printk_cpu_sync_put_irqrestore(flags);
}

asmlinkage __visible void dump_stack(void)
{
    dump_stack_lvl(KERN_DEFAULT);
}
