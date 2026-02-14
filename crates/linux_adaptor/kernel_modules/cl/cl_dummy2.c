#include <linux/cache.h>
#include <linux/cpumask.h>
#include <linux/crash_dump.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>

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

// kernel/time/timer.c
__visible u64 jiffies_64 __cacheline_aligned_in_smp = INITIAL_JIFFIES;

// init/main.c:
enum system_states system_state __read_mostly;

// mm/show_mem.c
atomic_long_t _totalram_pages __read_mostly;

// kernel/user.c
struct user_namespace init_user_ns = {
};

// kernel/utsname.c
const struct proc_ns_operations utsns_operations;

// kernel/workqueue.c
struct workqueue_struct *system_wq __ro_after_init;

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
