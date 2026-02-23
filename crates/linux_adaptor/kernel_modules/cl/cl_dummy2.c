#include <linux/cache.h>
#include <linux/cpumask.h>
#include <linux/crash_dump.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/suspend.h>
#include <uapi/linux/perf_event.h>

#include <net/sock.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

// lib/uuid.c
const u8 guid_index[16] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
const u8 uuid_index[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

// kernel/elfcorehdr.c
/*
 * stores the physical address of elf header of crash image
 *
 * Note: elfcorehdr_addr is not just limited to vmcore. It is also used by
 * is_kdump_kernel() to determine if we are booting after a panic. Hence put
 * it under CONFIG_CRASH_DUMP and not CONFIG_PROC_VMCORE.
 */
unsigned long long elfcorehdr_addr = ELFCORE_ADDR_MAX;
EXPORT_SYMBOL_GPL(elfcorehdr_addr);

// kernel/elfcorehdr.c
/*
 * stores the size of elf header of crash image
 */
unsigned long long elfcorehdr_size;

// init/main.c:
enum system_states system_state __read_mostly;

// mm/show_mem.c
atomic_long_t _totalram_pages __read_mostly;

// kernel/utsname.c
const struct proc_ns_operations utsns_operations;

// kernel/ksysfs.c
struct kobject *kernel_kobj;

// init/main.c
/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly;

// kernel/ksysfs.c
int rcu_normal;
int rcu_expedited;

// kernel/trace/trace.c
void disable_trace_on_warning(void)
{
}

// kernel/panic.c
void __warn(const char *file, int line, void *caller, unsigned taint,
        struct pt_regs *regs, struct warn_args *args)
{
    if (file)
        pr_warn("WARNING: CPU: %d PID: %d at %s:%d %pS\n",
            raw_smp_processor_id(), current->pid, file, line,
            caller);
    else
        pr_warn("WARNING: CPU: %d PID: %d at %pS\n",
            raw_smp_processor_id(), current->pid, caller);
}

// kernel/kallsyms.c
int sprint_symbol(char *buffer, unsigned long addr)
{
    *buffer = '\0';
    return 0;
}

// kernel/sched/isolation.c
DEFINE_STATIC_KEY_FALSE(housekeeping_overridden);

// drivers/base/arch_topology.c
DEFINE_PER_CPU(unsigned long, cpu_scale) = SCHED_CAPACITY_SCALE;

// kernel/power/suspend.c
enum s2idle_states __read_mostly s2idle_state;
static DEFINE_RAW_SPINLOCK(s2idle_lock);

// drivers/cpufreq/cpufreq.c
DEFINE_PER_CPU(unsigned long, cpufreq_pressure);

// kernel/events/core.c
struct static_key perf_swevent_enabled[PERF_COUNT_SW_MAX];

// drivers/base/arch_topology.c
DEFINE_PER_CPU(unsigned long, arch_freq_scale) = SCHED_CAPACITY_SCALE;

// kernel/profile.c
int prof_on __read_mostly;

// kernel/events/uprobes.c
void __init uprobes_init(void)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/time/vsyscall.c
void update_vsyscall(struct timekeeper *tk)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/power/main.c
int register_pm_notifier(struct notifier_block *nb)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// security/security.c
int security_prepare_creds(struct cred *new, const struct cred *old, gfp_t gfp)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// security/keys/key.c
void key_put(struct key *key)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/events/core.c
int perf_event_init_task(struct task_struct *child, u64 clone_flags)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}
void perf_event_fork(struct task_struct *task)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/auditsc.c
int audit_alloc(struct task_struct *tsk)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// security/security.c
int security_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// ipc/sem.c
int copy_semundo(unsigned long clone_flags, struct task_struct *tsk)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// drivers/tty/tty_audit.c
/*
 *  tty_audit_fork  -   Copy TTY audit state for a new task
 *
 *  Set up TTY audit state in @sig from current.  @sig needs no locking.
 */
void tty_audit_fork(struct signal_struct *sig)
{
    sig->audit_tty = current->signal->audit_tty;
}

// net/core/net_namespace.c
struct net init_net;
EXPORT_SYMBOL(init_net);

// kernel/seccomp.c
void get_seccomp_filter(struct task_struct *tsk)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/events/uprobes.c
void uprobe_copy_process(struct task_struct *t, unsigned long flags)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/events/core.c
DEFINE_STATIC_KEY_FALSE(perf_sched_events);
DEFINE_PER_CPU(struct pt_regs, __perf_regs[4]);
void __perf_event_task_sched_out(struct task_struct *task,
                 struct task_struct *next)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
}
void __perf_event_task_sched_in(struct task_struct *prev,
                struct task_struct *task)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
}
void ___perf_sw_event(u32 event_id, u64 nr, struct pt_regs *regs, u64 addr)
{
    pr_err("--> NOTE: %s: No impl.\n", __func__);
}

// init/calibrate.c
unsigned long lpj_fine;
