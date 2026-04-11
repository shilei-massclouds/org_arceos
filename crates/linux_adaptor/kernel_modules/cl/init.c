#include <linux/init.h>
#include <linux/printk.h>

#include <asm/setup.h>
#include <linux/buildid.h>
#include <linux/cgroup.h>
#include <linux/cpu.h>
#include <linux/memblock.h>
#include <linux/pid_namespace.h>
#include <linux/sched/init.h>
#include <linux/sched/clock.h>
#include <linux/sched/isolation.h>
#include <linux/tick.h>
#include <linux/moduleparam.h>
#include <linux/kfence.h>
#include <linux/stackprotector.h>
#include <linux/init_syscalls.h>
#include <linux/binfmts.h>
#include <linux/rmap.h>
#include <linux/extable.h>
#include <linux/padata.h>

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

int devices_init(void);
int buses_init(void);
int classes_init(void);
int platform_bus_init(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line __ro_after_init;
unsigned int saved_command_line_len __ro_after_init;
/* Command line for parameter parsing */
static char *static_command_line;
/* Untouched extra command line */
static char *extra_command_line;
/* Extra init arguments */
static char *extra_init_args;

/* From 'init/main.c' */

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

/* From 'init/main.c' */
bool initcall_debug;

static __initdata DECLARE_COMPLETION(kthreadd_done);

/* From 'init/main.c' */
/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

#define bootconfig_found false
#define initargs_offs 0

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

DEFINE_STATIC_KEY_MAYBE_RO(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,
               randomize_kstack_offset);
DEFINE_PER_CPU(u32, kstack_offset);

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

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
static void __init setup_command_line(char *command_line)
{
    size_t len, xlen = 0, ilen = 0;

    if (extra_command_line)
        xlen = strlen(extra_command_line);
    if (extra_init_args) {
        extra_init_args = strim(extra_init_args); /* remove trailing space */
        ilen = strlen(extra_init_args) + 4; /* for " -- " */
    }

    len = xlen + strlen(boot_command_line) + ilen + 1;

    saved_command_line = memblock_alloc(len, SMP_CACHE_BYTES);
    if (!saved_command_line)
        panic("%s: Failed to allocate %zu bytes\n", __func__, len);

    len = xlen + strlen(command_line) + 1;

    static_command_line = memblock_alloc(len, SMP_CACHE_BYTES);
    if (!static_command_line)
        panic("%s: Failed to allocate %zu bytes\n", __func__, len);

    if (xlen) {
        /*
         * We have to put extra_command_line before boot command
         * lines because there could be dashes (separator of init
         * command line) in the command lines.
         */
        strcpy(saved_command_line, extra_command_line);
        strcpy(static_command_line, extra_command_line);
    }
    strcpy(saved_command_line + xlen, boot_command_line);
    strcpy(static_command_line + xlen, command_line);

    if (ilen) {
        /*
         * Append supplemental init boot args to saved_command_line
         * so that user can check what command line options passed
         * to init.
         * The order should always be
         * " -- "[bootconfig init-param][cmdline init-param]
         */
        if (initargs_offs) {
            len = xlen + initargs_offs;
            strcpy(saved_command_line + len, extra_init_args);
            len += ilen - 4;    /* strlen(extra_init_args) */
            strcpy(saved_command_line + len,
                boot_command_line + initargs_offs - 1);
        } else {
            len = strlen(saved_command_line);
            strcpy(saved_command_line + len, " -- ");
            len += 4;
            strcpy(saved_command_line + len, extra_init_args);
        }
    }

    saved_command_line_len = strlen(saved_command_line);
}

static bool __init obsolete_checksetup(char *line)
{
    const struct obs_kernel_param *p;
    bool had_early_param = false;

    p = __setup_start;
    do {
        int n = strlen(p->str);
        if (parameqn(line, p->str, n)) {
            if (p->early) {
                /* Already done in parse_early_param?
                 * (Needs exact match on param part).
                 * Keep iterating, as we can have early
                 * params and __setups of same names 8( */
                if (line[n] == '\0' || line[n] == '=')
                    had_early_param = true;
            } else if (!p->setup_func) {
                pr_warn("Parameter %s is obsolete, ignored\n",
                    p->str);
                return true;
            } else if (p->setup_func(line + n))
                return true;
        }
        p++;
    } while (p < __setup_end);

    return had_early_param;
}

/* Change NUL term back to "=", to make "param" the whole string. */
static void __init repair_env_string(char *param, char *val)
{
    if (val) {
        /* param=val or param="val"? */
        if (val == param+strlen(param)+1)
            val[-1] = '=';
        else if (val == param+strlen(param)+2) {
            val[-2] = '=';
            memmove(val-1, val, strlen(val)+1);
        } else
            BUG();
    }
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val,
				     const char *unused, void *arg)
{
	size_t len = strlen(param);

	/* Handle params aliased to sysctls */
	if (sysctl_is_alias(param))
		return 0;

	repair_env_string(param, val);

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strnchr(param, len, '.'))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], len+1))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static void __init print_unknown_bootoptions(void)
{
    char *unknown_options;
    char *end;
    const char *const *p;
    size_t len;

    if (panic_later || (!argv_init[1] && !envp_init[2]))
        return;

    /*
     * Determine how many options we have to print out, plus a space
     * before each
     */
    len = 1; /* null terminator */
    for (p = &argv_init[1]; *p; p++) {
        len++;
        len += strlen(*p);
    }
    for (p = &envp_init[2]; *p; p++) {
        len++;
        len += strlen(*p);
    }

    unknown_options = memblock_alloc(len, SMP_CACHE_BYTES);
    if (!unknown_options) {
        pr_err("%s: Failed to allocate %zu bytes\n",
            __func__, len);
        return;
    }
    end = unknown_options;

    for (p = &argv_init[1]; *p; p++)
        end += sprintf(end, " %s", *p);
    for (p = &envp_init[2]; *p; p++)
        end += sprintf(end, " %s", *p);

    /* Start at unknown_options[1] to skip the initial space */
    pr_notice("Unknown kernel command line parameters \"%s\", will be passed to user space.\n",
        &unknown_options[1]);
    memblock_free(unknown_options, len);
}

/* Anything after -- gets handed straight to init. */
static int __init set_init_arg(char *param, char *val,
                   const char *unused, void *arg)
{
    unsigned int i;

    if (panic_later)
        return 0;

    repair_env_string(param, val);

    for (i = 0; argv_init[i]; i++) {
        if (i == MAX_INIT_ARGS) {
            panic_later = "init";
            panic_param = param;
            return 0;
        }
    }
    argv_init[i] = param;
    return 0;
}

void __init __weak trap_init(void) { }

void cl_setup_arch_later(void)
{
    char *after_dashes;

    jump_label_init();
    unflatten_device_tree();
    misc_mem_init();
    setup_smp();
    riscv_init_cbo_blocksizes();
    riscv_fill_hwcap();

    setup_command_line(boot_command_line/* command_line */);
    setup_nr_cpu_ids();
    setup_per_cpu_areas();
    boot_cpu_hotplug_init();

    pr_notice("Kernel command line: %s\n", saved_command_line);
    /* parameters may set static keys */
    parse_early_param();
    after_dashes = parse_args("Booting kernel",
                  static_command_line, __start___param,
                  __stop___param - __start___param,
                  -1, -1, NULL, &unknown_bootoption);
    print_unknown_bootoptions();
    if (!IS_ERR_OR_NULL(after_dashes))
        parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
               NULL, set_init_arg);
    if (extra_init_args)
        parse_args("Setting extra init args", extra_init_args,
               NULL, 0, -1, -1, NULL, set_init_arg);

    /* Architectural and non-timekeeping rng init, before allocator init */
    random_init_early(boot_command_line/* command_line */);

    /*
     * These use large bootmem allocations and must precede
     * initalization of page allocator
     */
    //setup_log_buf(0);
    vfs_caches_init_early();
    sort_main_extable();
    trap_init();
}

void cl_init_irq(void)
{
    /*
     * irq depends on radix && maple
     */
    radix_tree_init();
    maple_tree_init();

    /*
     * Set up housekeeping before setting up workqueues to allow the unbound
     * workqueue to take non-housekeeping into account.
     */
    housekeeping_init();

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

    /* These make use of the fully initialized rng */
    kfence_init();
    boot_init_stack_canary();

#if 0
    perf_event_init();
    profile_init();
#endif
    call_function_init();
    WARN(!irqs_disabled(), "Interrupts were enabled early\n");

    early_boot_irqs_disabled = false;
    local_irq_enable();
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
    anon_vma_init();
#if 0
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
#endif
    vfs_caches_init();
    pagecache_init();
    signals_init();
}

void pin_task_on_cpu(int pid, unsigned int cpu_id)
{
    struct task_struct *tsk;

    /*
     * Pin init on the boot CPU. Task migration is not properly working
     * until sched_init_smp() has been run. It will set the allowed
     * CPUs for init to the non isolated CPUs.
     */
    rcu_read_lock();
    tsk = find_task_by_pid_ns(pid, &init_pid_ns);
    tsk->flags |= PF_NO_SETAFFINITY;
    set_cpus_allowed_ptr(tsk, cpumask_of(cpu_id));
    rcu_read_unlock();
}

static void __init do_pre_smp_initcalls(void)
{
    initcall_entry_t *fn;

    trace_initcall_level("early");
    for (fn = __initcall_start; fn < __initcall0_start; fn++)
        do_one_initcall(initcall_from_entry(fn));
}

void prepare_kernel_init()
{
    /*
     * Wait until kthreadd is all set-up.
     */
    wait_for_completion(&kthreadd_done);
}

void init_smp(void)
{
    smp_prepare_cpus(setup_max_cpus);

    workqueue_init();

#if 0
    init_mm_internals();

    rcu_init_tasks_generic();
#endif
    do_pre_smp_initcalls();
#if 0
    lockup_detector_init();
#endif

    smp_init();
    sched_init_smp();
}

void init_page_alloc_later()
{
#if 0
    workqueue_init_topology();
    async_init();
#endif
    padata_init();
    page_alloc_init_late();
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
    devices_init();
    buses_init();
    classes_init();
    platform_bus_init();
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
    for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++) {
        printk("%s: --- level(%s) ---\n", __func__, initcall_level_names[level]);
        do_one_initcall(initcall_from_entry(fn));
    }
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

void cl_do_initcalls(void)
{
    do_initcalls();
}

void cl_prepare_namespace(void)
{
    prepare_namespace();
}

void linux_idle_loop(pid_t pid)
{
    /*
     * Enable might_sleep() and smp_processor_id() checks.
     * They cannot be enabled earlier because with CONFIG_PREEMPTION=y
     * kernel_thread() would trigger might_sleep() splats. With
     * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
     * already, but it's stuck on the kthreadd_done completion.
     */
    system_state = SYSTEM_SCHEDULING;

    complete(&kthreadd_done);

    /*
     * The boot idle thread must execute schedule()
     * at least once to get things moving:
     */
    schedule_preempt_disabled();
    /* Call into cpu_idle with preempt disabled */
    cpu_startup_entry(CPUHP_ONLINE);
}

void cl_free_init_mem()
{
    system_state = SYSTEM_FREEING_INITMEM;
#if 0
    kprobe_free_init_mem();
    ftrace_free_init_mem();
    kgdb_free_init_mem();
    exit_boot_config();
    free_initmem();
    mark_readonly();

    /*
     * Kernel mappings are now finalized - update the userspace page-table
     * to finalize PTI.
     */
    pti_finalize();
#endif

    system_state = SYSTEM_RUNNING;
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val,
                 const char *unused, void *arg)
{
    const struct obs_kernel_param *p;

    for (p = __setup_start; p < __setup_end; p++) {
        if ((p->early && parameq(param, p->str)) ||
            (strcmp(param, "console") == 0 &&
             strcmp(p->str, "earlycon") == 0)
        ) {
            if (p->setup_func(val) != 0)
                pr_warn("Malformed early option '%s'\n", param);
        }
    }
    /* We accept everything at this stage. */
    return 0;
}

void __init parse_early_options(char *cmdline)
{
    parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
           do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
    static int done __initdata;
    static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

    if (done)
        return;

    /* All fall through to do_early_param. */
    strscpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
    parse_early_options(tmp_cmdline);
    done = 1;
}

static int run_init_process(const char *init_filename)
{
    const char *const *p;

    argv_init[0] = init_filename;
    pr_info("Run %s as init process\n", init_filename);
    pr_debug("  with arguments:\n");
    for (p = argv_init; *p; p++)
        pr_debug("    %s\n", *p);
    pr_debug("  with environment:\n");
    for (p = envp_init; *p; p++)
        pr_debug("    %s\n", *p);
    return kernel_execve(init_filename, argv_init, envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
    int ret;

    ret = run_init_process(init_filename);

    if (ret && ret != -ENOENT) {
        pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
               init_filename, ret);
    }

    return ret;
}

int cl_try_to_run_init_process(const char *init_filename)
{
    return try_to_run_init_process(init_filename);
}
