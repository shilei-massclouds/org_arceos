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
    if (core_kernel_text(addr))
        return 1;

    PANIC("");
    return 0;
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
