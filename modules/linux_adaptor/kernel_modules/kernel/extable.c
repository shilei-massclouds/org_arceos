#include <linux/elf.h>
#include <linux/ftrace.h>
#include <linux/memory.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/filter.h>

#include <asm/sections.h>
#include <linux/uaccess.h>

#include "../adaptor.h"

/*
 * mutex protecting text section modification (dynamic code patching).
 * some users need to sleep (allocating memory...) while they hold this lock.
 *
 * Note: Also protects SMP-alternatives modification on x86.
 *
 * NOT exported to modules - patching kernel text is a really delicate matter.
 */
DEFINE_MUTEX(text_mutex);

int notrace core_kernel_text(unsigned long addr)
{
    if (is_kernel_text(addr))
        return 1;

    return 0;
}

int kernel_text_address(unsigned long addr)
{
    bool no_rcu;
    int ret = 1;

    if (core_kernel_text(addr))
        return 1;

    /*
     * If a stack dump happens while RCU is not watching, then
     * RCU needs to be notified that it requires to start
     * watching again. This can happen either by tracing that
     * triggers a stack trace, or a WARN() that happens during
     * coming back from idle, or cpu on or offlining.
     *
     * is_module_text_address() as well as the kprobe slots,
     * is_bpf_text_address() and is_bpf_image_address require
     * RCU to be watching.
     */
    no_rcu = !rcu_is_watching();

    /* Treat this like an NMI as it can happen anywhere */
    if (no_rcu)
        ct_nmi_enter();

    if (is_module_text_address(addr))
        goto out;
    if (is_ftrace_trampoline(addr))
        goto out;
    if (is_kprobe_optinsn_slot(addr) || is_kprobe_insn_slot(addr))
        goto out;
    if (is_bpf_text_address(addr))
        goto out;
    ret = 0;
out:
    if (no_rcu)
        ct_nmi_exit();

    return ret;
}

int __kernel_text_address(unsigned long addr)
{
    if (kernel_text_address(addr))
        return 1;
    /*
     * There might be init symbols in saved stacktraces.
     * Give those symbols a chance to be printed in
     * backtraces (such as lockdep traces).
     *
     * Since we are after the module-symbols check, there's
     * no danger of address overlap:
     */
    if (is_kernel_inittext(addr))
        return 1;
    return 0;
}
