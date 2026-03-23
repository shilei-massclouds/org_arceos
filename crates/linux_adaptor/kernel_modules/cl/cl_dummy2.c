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

#ifdef CL_SHOW_DUMMY
#define pr_dummy(fmt, ...) \
    printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#else
#define pr_dummy(fmt, ...)
#endif

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
unsigned long totalcma_pages __read_mostly;

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

// drivers/base/arch_topology.c
DEFINE_PER_CPU(unsigned long, cpu_scale) = SCHED_CAPACITY_SCALE;

// kernel/power/suspend.c
enum s2idle_states __read_mostly s2idle_state;
static DEFINE_RAW_SPINLOCK(s2idle_lock);

// drivers/cpufreq/cpufreq.c
DEFINE_PER_CPU(unsigned long, cpufreq_pressure);

// kernel/profile.c
int prof_on __read_mostly;

// kernel/events/uprobes.c
void __init uprobes_init(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/time/vsyscall.c
void update_vsyscall(struct timekeeper *tk)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/power/main.c
int register_pm_notifier(struct notifier_block *nb)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// security/security.c
int security_prepare_creds(struct cred *new, const struct cred *old, gfp_t gfp)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_task_setscheduler(struct task_struct *p)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// security/keys/key.c
void key_put(struct key *key)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/events/core.c
struct static_key perf_swevent_enabled[PERF_COUNT_SW_MAX];

int perf_event_init_task(struct task_struct *child, u64 clone_flags)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}
void perf_event_fork(struct task_struct *task)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void perf_event_comm(struct task_struct *task, bool exec)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int perf_event_init_cpu(unsigned int cpu)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// kernel/auditsc.c
int audit_alloc(struct task_struct *tsk)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// ipc/sem.c
int copy_semundo(unsigned long clone_flags, struct task_struct *tsk)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}
void exit_sem(struct task_struct *tsk)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
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
struct net init_net = {
    .ns.count = 1,
};
EXPORT_SYMBOL(init_net);

// kernel/seccomp.c
void get_seccomp_filter(struct task_struct *tsk)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void seccomp_filter_release(struct task_struct *tsk)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/events/uprobes.c
void uprobe_copy_process(struct task_struct *t, unsigned long flags)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/events/core.c
DEFINE_STATIC_KEY_FALSE(perf_sched_events);
DEFINE_PER_CPU(struct pt_regs, __perf_regs[4]);
void __perf_event_task_sched_out(struct task_struct *task,
                 struct task_struct *next)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}
void __perf_event_task_sched_in(struct task_struct *prev,
                struct task_struct *task)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}
void ___perf_sw_event(u32 event_id, u64 nr, struct pt_regs *regs, u64 addr)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// init/calibrate.c
unsigned long lpj_fine;

// kernel/events/core.c
void perf_event_task_tick(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/profile.c
void profile_tick(int type)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// io_uring/io_uring.c
void __io_uring_cancel(bool cancel_all)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// drivers/tty/tty_audit.c
void tty_audit_exit(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/events/core.c
void perf_event_exit_task(struct task_struct *child)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/futex/core.c
void futex_exit_release(struct task_struct *tsk)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/events/uprobes.c
void uprobe_free_utask(struct task_struct *t)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// ipc/shm.c
void exit_shm(struct task_struct *task)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// fs/file.c
void exit_files(struct task_struct *tsk)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// drivers/tty/tty_jobctrl.c
void disassociate_ctty(int on_exit)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/panic.c
extern int cl_vprintk(const char *, va_list);

void __warn_printk(const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
    r = cl_vprintk(fmt, args);
	va_end(args);

	return r;
}

// kernel/watchdog.c
int lockup_detector_online_cpu(unsigned int cpu)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// drivers/base/bus.c
int subsys_virtual_register(const struct bus_type *subsys,
                const struct attribute_group **groups)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// fs/proc/proc_sysctl.c
struct ctl_table_header *register_sysctl_sz(const char *path, struct ctl_table *table,
                        size_t table_size)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return NULL;
}

// drivers/base/syscore.c
void register_syscore_ops(struct syscore_ops *ops)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// fs/debugfs/inode.c
struct dentry *debugfs_create_dir(const char *name, struct dentry *parent)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return NULL;
}

struct dentry *debugfs_create_file(const char *name, umode_t mode,
                   struct dentry *parent, void *data,
                   const struct file_operations *fops)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return NULL;
}

// fs/proc/proc_sysctl.c
void __init __register_sysctl_init(const char *path, struct ctl_table *table,
                 const char *table_name, size_t table_size)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// fs/sysfs/dir.c
int sysfs_create_dir_ns(struct kobject *kobj, const void *ns)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int sysfs_create_groups(struct kobject *kobj,
            const struct attribute_group **groups)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// fs/kernfs/mount.c
void __init kernfs_init(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void kernfs_get(struct kernfs_node *kn)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// fs/sysfs/file.c
int sysfs_create_file_ns(struct kobject *kobj, const struct attribute *attr,
             const void *ns)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void sysfs_remove_file_ns(struct kobject *kobj, const struct attribute *attr,
              const void *ns)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void sysfs_remove_groups(struct kobject *kobj,
             const struct attribute_group **groups)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void sysfs_delete_link(struct kobject *kobj, struct kobject *targ,
            const char *name)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// drivers/base/power/sysfs.c
int dpm_sysfs_add(struct device *dev)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// net/core/skbuff.c
void consume_skb(struct sk_buff *skb)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int sysfs_create_link(struct kobject *kobj, struct kobject *target,
              const char *name)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int sysfs_create_group(struct kobject *kobj,
               const struct attribute_group *grp)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void sysfs_remove_link(struct kobject *kobj, const char *name)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// FixMe
// drivers/pci/pci-driver.c
const struct bus_type pci_bus_type;

// kernel/hung_task.c
/*
 * Zero means infinite timeout - no checking done:
 */
unsigned long __read_mostly sysctl_hung_task_timeout_secs = CONFIG_DEFAULT_HUNG_TASK_TIMEOUT;

struct proc_dir_entry *proc_create_seq_private(const char *name, umode_t mode,
        struct proc_dir_entry *parent, const struct seq_operations *ops,
        unsigned int state_size, void *data)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return NULL;
}

struct proc_dir_entry *proc_create_single_data(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        int (*show)(struct seq_file *, void *), void *data)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return NULL;
}

int security_fs_context_parse_param(struct fs_context *fc,
                    struct fs_parameter *param)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_sb_alloc(struct super_block *sb)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_bdev_alloc(struct block_device *bdev)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

kuid_t make_kuid(struct user_namespace *ns, uid_t uid)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return KUIDT_INIT(0);
}

kgid_t make_kgid(struct user_namespace *ns, gid_t gid)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return KGIDT_INIT(0);
}

int security_inode_alloc(struct inode *inode, gfp_t gfp)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void security_d_instantiate(struct dentry *dentry, struct inode *inode)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_sb_set_mnt_opts(struct super_block *sb,
                 void *mnt_opts,
                 unsigned long kern_flags,
                 unsigned long *set_kern_flags)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int __init sysfs_init(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void security_free_mnt_opts(void **mnt_opts)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int proc_alloc_inum(unsigned int *inum)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_file_alloc(struct file *file)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// kernel/sysctl.c
const unsigned long sysctl_long_vals[] = { 0, 1, LONG_MAX };
EXPORT_SYMBOL_GPL(sysctl_long_vals);

// mm/show_mem.c
unsigned long totalreserve_pages __read_mostly;

int security_inode_permission(struct inode *inode, int mask)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_file_permission(struct file *file, int mask)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// fs/proc/generic.c
struct proc_dir_entry *proc_mkdir(const char *name,
        struct proc_dir_entry *parent)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return NULL;
}

// init/do_mounts_initrd.c
bool __init initrd_load(char *root_device_name)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return false;
}

// security/security.c
void security_file_release(struct file *file)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void security_file_free(struct file *file)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// fs/proc/proc_sysctl.c
bool sysctl_is_alias(char *param)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return false;
}

int security_path_mkdir(const struct path *dir, struct dentry *dentry,
            umode_t mode)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// kernel/umh.c
void __usermodehelper_set_disable_depth(enum umh_disable_depth depth)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_inode_init_security(struct inode *inode, struct inode *dir,
                 const struct qstr *qstr,
                 const initxattrs initxattrs, void *fs_data)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_path_mknod(const struct path *dir, struct dentry *dentry,
            umode_t mode, unsigned int dev)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_inode_mknod(struct inode *dir, struct dentry *dentry,
             umode_t mode, dev_t dev)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// kernel/capability.c
bool capable(int cap)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return true;
}

bool ns_capable(struct user_namespace *ns, int cap)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return true;
}

int security_sb_mount(const char *dev_name, const struct path *path,
              const char *type, unsigned long flags, void *data)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}
