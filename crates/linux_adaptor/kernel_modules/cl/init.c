#include <linux/init.h>
#include <linux/printk.h>

#include <asm/setup.h>
#include <linux/buildid.h>
#include <linux/cgroup.h>
#include <linux/cpu.h>
#include <linux/memblock.h>

#include "adaptor.h"

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

/*
 * start_kernel() [init/main.c]
 *   - the first part before setup_arch()
 */
void cl_early_init(unsigned long hartid, unsigned long dtb_pa)
{
    set_task_stack_end_magic(&init_task);
    smp_setup_processor_id();
    debug_objects_early_init();
    init_vmlinux_build_id();

    cgroup_init_early();

    local_irq_disable();
    early_boot_irqs_disabled = true;

    /*
     * Interrupts are still disabled. Do necessary setups, then
     * enable them.
     */
    boot_cpu_init();
    page_address_init();
    pr_notice("%s", linux_banner);

    /* setup_arch() will called in crate 'membloc'. */
    //setup_arch(NULL /* cmdline_p */);
}
