#include <linux/init.h>
#include <linux/printk.h>

#include <asm/setup.h>
#include <linux/buildid.h>
#include <linux/cgroup.h>
#include <linux/cpu.h>
#include <linux/memblock.h>
#include <linux/pid_namespace.h>

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
 * early stage in start_kernel() [init/main.c]
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

/*
 * late stage in start_kernel() [init/main.c]
 *   - the last part before kernel_init kthread being scheduling
 */
void cl_late_init()
{
    pid_idr_init();
#if 0
    anon_vma_init();
    thread_stack_cache_init();
#endif

    cred_init();
    fork_init();
    proc_caches_init();
#if 0
    uts_ns_init();
    key_init();
    security_init();
    dbg_late_init();
    net_ns_init();
    vfs_caches_init();
    pagecache_init();
#endif
    signals_init();
}
