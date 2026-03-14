#include <linux/init.h>
#include <linux/printk.h>

#include <asm/setup.h>
#include <linux/buildid.h>
#include <linux/cgroup.h>
#include <linux/cpu.h>
#include <linux/memblock.h>
#include <linux/pid_namespace.h>
#include <linux/sched/clock.h>
#include <linux/tick.h>

#define CREATE_TRACE_POINTS
#include <trace/events/initcall.h>

#include "adaptor.h"

#define do_trace_initcall_start    trace_initcall_start
#define do_trace_initcall_finish   trace_initcall_finish

void parse_dtb(void);
void sbi_init(void);
void setup_bootmem(void);
void unflatten_device_tree(void);
void riscv_init_cbo_blocksizes(void);

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

static initcall_entry_t *initcall_levels[] __initdata = {
    __initcall0_start,
    __initcall1_start,
    __initcall2_start,
    __initcall3_start,
    __initcall4_start,
    __initcall5_start,
    __initcall6_start,
    __initcall7_start,
    __initcall_end,
};

static const char *initcall_level_names[] __initdata = {
    "pure",
    "core",
    "postcore",
    "arch",
    "subsys",
    "fs",
    "device",
    "late",
};

/*
 * early stage before setup_arch in start_kernel [init/main.c]
 */
void cl_setup_arch_earlier(void)
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
    pr_notice("%s\n", linux_banner);
}

/*
 * setup memblock in setup_arch.
 */
void cl_setup_bootmem(void)
{
    //
    // parse_dtb() [arch/riscv/kernel/setup.c]
    //   - get physical memory range from fdt
    //
    // sbi_init() [arch/riscv/kernel/setup.c]
    //
    // setup_bootmem() [arch/riscv/mm/init.c]
    //   - reserve areas including kernel, initrd and fdt
    //
    parse_dtb();
    sbi_init();
    setup_bootmem();
}

void cl_setup_arch_later(void)
{
    jump_label_init();
    unflatten_device_tree();
    misc_mem_init();
    setup_smp();
    riscv_init_cbo_blocksizes();
    riscv_fill_hwcap();

    setup_nr_cpu_ids();
    setup_per_cpu_areas();
    boot_cpu_hotplug_init();
    random_init_early(boot_command_line/* command_line */);
}

void cl_init_irq(void)
{
    /*
     * irq depends on radix && maple
     */
    radix_tree_init();
    maple_tree_init();

    /*
     * Allow workqueue creation and work item queueing/cancelling
     * early.  Work item execution depends on kthreads and starts after
     * workqueue_init().
     */
    workqueue_init_early();
    rcu_init();

    /* init some links before init_ISA_irqs() */
    early_irq_init();
    init_IRQ();
    tick_init();
    //rcu_init_nohz();
    init_timers();
    //srcu_init();
    hrtimers_init();

    softirq_init();
    timekeeping_init();
    time_init();

    /* This must be after timekeeping is initialized */
    random_init();
}

/*
 * late stage in start_kernel() [init/main.c]
 *   - the last part before kernel_init kthread being scheduling
 */
void start_sched_earlier()
{
#if 0
    setup_per_cpu_pageset();
    numa_policy_init();
    acpi_early_init();
    if (late_time_init)
        late_time_init();
#endif
    sched_clock_init();
#if 0
    calibrate_delay();

    arch_cpu_finalize_init();
#endif

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

void start_kthreadd(void)
{
    int pid;

    pid = kernel_thread(kthreadd, NULL, NULL, CLONE_FS | CLONE_FILES);
    rcu_read_lock();
    kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
    rcu_read_unlock();
}

static void __init do_pre_smp_initcalls(void)
{
    initcall_entry_t *fn;

    trace_initcall_level("early");
    for (fn = __initcall_start; fn < __initcall0_start; fn++)
        do_one_initcall(initcall_from_entry(fn));
}

void init_smp(void)
{
    smp_prepare_cpus(setup_max_cpus);

#if 0
    workqueue_init();

    init_mm_internals();

    rcu_init_tasks_generic();
#endif
    do_pre_smp_initcalls();
#if 0
    lockup_detector_init();
#endif

    smp_init();
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
    // FixMe: impl it.
    return false;
}

int __init_or_module do_one_initcall(initcall_t fn)
{
    int count = preempt_count();
    char msgbuf[64];
    int ret;

    if (initcall_blacklisted(fn))
        return -EPERM;

    do_trace_initcall_start(fn);
    ret = fn();
    do_trace_initcall_finish(fn, ret);

    msgbuf[0] = 0;

    if (preempt_count() != count) {
        sprintf(msgbuf, "preemption imbalance ");
        preempt_count_set(count);
    }
    if (irqs_disabled()) {
        strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
        local_irq_enable();
    }
    WARN(msgbuf[0], "initcall %pS returned with %s\n", fn, msgbuf);

    add_latent_entropy();
    return ret;
}

void cl_driver_init()
{
    //PANIC("");
    printk("%s: Warning!!! -------------------- IMPL IT ------------------------------\n", __func__);
}

static int __init ignore_unknown_bootoption(char *param, char *val,
                   const char *unused, void *arg)
{
    return 0;
}

static void __init do_initcall_level(int level, char *command_line)
{
    initcall_entry_t *fn;

    parse_args(initcall_level_names[level],
           command_line, __start___param,
           __stop___param - __start___param,
           level, level,
           NULL, ignore_unknown_bootoption);

    trace_initcall_level(initcall_level_names[level]);
    for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
        do_one_initcall(initcall_from_entry(fn));
}

static void __init do_initcalls(void)
{
    int level;
    size_t len = saved_command_line_len + 1;
    char *command_line;

    command_line = kzalloc(len, GFP_KERNEL);
    if (!command_line)
        panic("%s: Failed to allocate %zu bytes\n", __func__, len);

    for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++) {
        /* Parser modifies command_line, restore it each time */
        strcpy(command_line, saved_command_line);
        do_initcall_level(level, command_line);
    }

    kfree(command_line);
}

void cl_do_initcalls()
{
    PANIC("");
}
