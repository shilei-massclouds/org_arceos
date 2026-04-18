#include <linux/cache.h>
#include <linux/cpumask.h>
#include <linux/crash_dump.h>
#include <linux/percpu_counter.h>
#include <linux/jump_label.h>
#include <linux/btf_ids.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/suspend.h>
#include <linux/audit.h>
#include <linux/ethtool.h>
#include <linux/in6.h>
#include <linux/pipe_fs_i.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <uapi/linux/perf_event.h>

#include <net/dst.h>
#include <net/genetlink.h>
#include <net/hotdata.h>
#include <net/ip.h>
#include <net/ip_fib.h>
#include <net/ip_tunnels.h>
#include <net/fib_notifier.h>
#include <net/l3mdev.h>
#include <net/nexthop.h>
#include <net/neighbour.h>
#include <net/protocol.h>
#include <net/ping.h>
#include <net/raw.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "../net/ipv4/fib_lookup.h"

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

	va_start(args, fmt);
    cl_vprintk(fmt, args);
	va_end(args);
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
    return (struct proc_dir_entry *)1;
}

struct proc_dir_entry *proc_create_single_data(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        int (*show)(struct seq_file *, void *), void *data)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return (struct proc_dir_entry *)1;
}

int security_fs_context_parse_param(struct fs_context *fc,
                    struct fs_parameter *param)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return -ENOPARAM;
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

void __init crypto_init_proc(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_task_setioprio(struct task_struct *p, int ioprio)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void security_sb_free(struct super_block *sb)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_sb_kern_mount(const struct super_block *sb)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_path_chroot(const struct path *path)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_inode_getattr(const struct path *path)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_inode_create(struct inode *dir, struct dentry *dentry,
              umode_t mode)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_file_open(struct file *file)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_file_post_open(struct file *file, int mask)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// fs/notify/dnotify/dnotify.c
void dnotify_flush(struct file *filp, fl_owner_t id)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_path_truncate(const struct path *path)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_inode_need_killpriv(struct dentry *dentry)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_inode_setattr(struct mnt_idmap *idmap,
               struct dentry *dentry, struct iattr *attr)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_inode_killpriv(struct mnt_idmap *idmap,
                struct dentry *dentry)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void security_inode_post_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
                 int ia_valid)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void security_inode_free(struct inode *inode)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_path_unlink(const struct path *dir, struct dentry *dentry)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_path_rmdir(const struct path *dir, struct dentry *dentry)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void tty_kref_put(struct tty_struct *tty)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// fs/proc/base.c
void proc_flush_pid(struct pid *pid)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void perf_event_delayed_put(struct task_struct *task)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void __io_uring_free(struct task_struct *tsk)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void security_task_free(struct task_struct *task)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void security_cred_free(struct cred *cred)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void groups_free(struct group_info *group_info)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void bpf_task_storage_free(struct task_struct *task)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_inode_follow_link(struct dentry *dentry, struct inode *inode,
                   bool rcu)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_vm_enough_memory_mm(struct mm_struct *mm, long pages)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_bprm_creds_for_exec(struct linux_binprm *bprm)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_bprm_check(struct linux_binprm *bprm)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// kernel/events/uprobes.c
void uprobe_clear_state(struct mm_struct *mm)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_bprm_creds_from_file(struct linux_binprm *bprm, const struct file *file)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void perf_event_exec(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void security_bprm_committing_creds(const struct linux_binprm *bprm)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void key_fsgid_changed(struct cred *new_cred)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void key_fsuid_changed(struct cred *new_cred)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void security_bprm_committed_creds(const struct linux_binprm *bprm)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// security/min_addr.c
/* amount of vm to protect from userspace access by both DAC and the LSM*/
unsigned long mmap_min_addr;
/* amount of vm to protect from userspace using CAP_SYS_RAWIO (DAC) */
unsigned long dac_mmap_min_addr = CONFIG_DEFAULT_MMAP_MIN_ADDR;

void perf_event_mmap(struct vm_area_struct *vma)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_mmap_file(struct file *file, unsigned long prot,
               unsigned long flags)

{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_mmap_addr(unsigned long addr)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int uprobe_mmap(struct vm_area_struct *vma)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void uprobe_munmap(struct vm_area_struct *vma, unsigned long start, unsigned long end)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/printk/printk.c
void console_unblank(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void wake_up_klogd(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void uprobe_notify_resume(struct pt_regs *regs)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/audit.c
u32     audit_enabled = AUDIT_OFF;

// fs/hugetlbfs/inode.c
int sysctl_hugetlb_shm_group;

struct dentry *debugfs_create_file_unsafe(const char *name, umode_t mode,
                   struct dentry *parent, void *data,
                   const struct file_operations *fops)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return NULL;
}

void debugfs_create_u32(const char *name, umode_t mode, struct dentry *parent,
            u32 *value)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
               unsigned long prot)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

bool uprobe_deny_signal(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return false;
}

int security_task_getscheduler(struct task_struct *p)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void uprobe_start_dup_mmap(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void uprobe_end_dup_mmap(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void uprobe_dup_mmap(struct mm_struct *oldmm, struct mm_struct *newmm)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// kernel/sysctl.c
/* shared constants to be used in various sysctls */
const int sysctl_vals[] = { 0, 1, 2, 3, 4, 100, 200, 1000, 3000, INT_MAX, 65535, -1 };
EXPORT_SYMBOL(sysctl_vals);

int security_sb_statfs(struct dentry *dentry)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_file_lock(struct file *file, unsigned int cmd)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int net_sysctl_init(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// net/ipv4/protocol.c
// net/core/hotdata.c
struct net_hotdata net_hotdata __cacheline_aligned = {
    .offload_base = LIST_HEAD_INIT(net_hotdata.offload_base),
    .ptype_all = LIST_HEAD_INIT(net_hotdata.ptype_all),
};

int security_socket_create(int family, int type, int protocol, int kern)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_socket_post_create(struct socket *sock, int family,
                int type, int protocol, int kern)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// net/core/dst.c
const struct dst_metrics dst_default_metrics = {
    /* This initializer is needed to force linker to place this variable
     * into const section. Otherwise it might end into bss section.
     * We really want to avoid false sharing on this variable, and catch
     * any writes on it.
     */
    .refcnt = REFCOUNT_INIT(1),
};
EXPORT_SYMBOL(dst_default_metrics);

// net/core/filter.c
DEFINE_STATIC_KEY_FALSE(bpf_master_redirect_enabled_key);
EXPORT_SYMBOL_GPL(bpf_master_redirect_enabled_key);

struct proc_dir_entry *_proc_mkdir(const char *name, umode_t mode,
        struct proc_dir_entry *parent, void *data, bool force_lookup)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return NULL;
}

int __init dev_proc_init(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int __init netdev_kobject_init(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int netdev_register_kobject(struct net_device *ndev)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void netdev_unregister_kobject(struct net_device *ndev)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int net_rx_queue_update_kobjects(struct net_device *dev, int old_num, int new_num)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int netdev_queue_update_kobjects(struct net_device *dev, int old_num, int new_num)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

struct proc_dir_entry *proc_create_net_data(const char *name, umode_t mode,
        struct proc_dir_entry *parent, const struct seq_operations *ops,
        unsigned int state_size, void *data)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return (struct proc_dir_entry *)1;
}

struct proc_dir_entry *proc_create_net_single(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        int (*show)(struct seq_file *, void *), void *data)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return (struct proc_dir_entry *)1;
}

int security_inode_listsecurity(struct inode *inode,
                char *buffer, size_t buffer_size)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_sk_alloc(struct sock *sk, int family, gfp_t priority)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

void security_sk_classify_flow(const struct sock *sk, struct flowi_common *flic)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

void security_sock_graft(struct sock *sk, struct socket *parent)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

int security_inet_conn_request(const struct sock *sk,
        struct sk_buff *skb, struct request_sock *req)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_socket_recvmsg(struct socket *sock, struct msghdr *msg,
                int size, int flags)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

// net/core/flow_dissector.c
struct flow_dissector flow_keys_basic_dissector __read_mostly;
EXPORT_SYMBOL(flow_keys_basic_dissector);

// net/core/filter.c
const struct bpf_func_proto bpf_sk_setsockopt_proto;
const struct bpf_func_proto bpf_sk_getsockopt_proto;
u32 btf_sock_ids[32];

// net/ipv6/protocol.c
const struct net_offload __rcu *inet6_offloads[MAX_INET_PROTOS];

// net/ipv4/ip_sockglue.c
DEFINE_STATIC_KEY_FALSE(ip4_min_ttl);

// net/ipv4/fib_semantics.c
const struct fib_prop fib_props[RTN_MAX + 1];

// net/core/sysctl_net_core.c
int sysctl_devconf_inherit_init_net;

// net/ipv4/tcp_input.c
int sysctl_tcp_max_orphans;

// net/core/filter.c
DEFINE_STATIC_KEY_FALSE(bpf_sk_lookup_enabled);

int ip_misc_proc_init(void)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}


// fs/seq_file.c
void seq_pad(struct seq_file *m, char c)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
}

// net/core/netevent.c
int call_netevent_notifiers(unsigned long val, void *v)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

struct ctl_table_header *register_net_sysctl_sz(struct net *net, const char *path,
        struct ctl_table *table, size_t table_size)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return (struct ctl_table_header *)1;
}

// kernel/sysctl.c proc helpers
int proc_dointvec_ms_jiffies_minmax(const struct ctl_table *table, int write,
        void *buffer, size_t *lenp, loff_t *ppos)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int proc_dointvec_userhz_jiffies(const struct ctl_table *table, int write,
        void *buffer, size_t *lenp, loff_t *ppos)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

int proc_dointvec_ms_jiffies(const struct ctl_table *table, int write,
        void *buffer, size_t *lenp, loff_t *ppos)
{
    pr_dummy("--> NOTE: %s: No impl.\n", __func__);
    return 0;
}

u32 l3mdev_fib_table_rcu(const struct net_device *dev)
{
    return 0;
}

struct nexthop *nexthop_find_by_id(struct net *net, u32 id)
{
    return NULL;
}

int fib_sync_down_dev(struct net_device *dev, unsigned long event, bool force)
{
    return 0;
}

int fib_sync_down_addr(struct net_device *dev, __be32 local)
{
    return 0;
}

int fib_sync_up(struct net_device *dev, unsigned char nh_flags)
{
    return 0;
}

void fib_sync_mtu(struct net_device *dev, u32 orig_mtu)
{
}

void workqueue_softirq_action(bool highpri)
{
}

void xfrm_init(void)
{
}

void xfrm4_init(void)
{
}

int call_fib_notifier(struct notifier_block *nb,
        enum fib_event_type event_type, struct fib_notifier_info *info)
{
    return 0;
}

int call_fib_notifiers(struct net *net, enum fib_event_type event_type,
        struct fib_notifier_info *info)
{
    return 0;
}

struct fib_notifier_ops *
fib_notifier_ops_register(const struct fib_notifier_ops *tmpl, struct net *net)
{
    return (struct fib_notifier_ops *)1;
}

void fib_notifier_ops_unregister(struct fib_notifier_ops *ops)
{
}

size_t fib_nlmsg_size(struct fib_info *fi)
{
    return 0;
}

struct fib_info *fib_create_info(struct fib_config *cfg,
        struct netlink_ext_ack *extack)
{
    return NULL;
}

void fib_release_info(struct fib_info *fi)
{
}

int fib_nh_match(struct net *net, struct fib_config *cfg, struct fib_info *fi,
        struct netlink_ext_ack *extack)
{
    return 0;
}

bool fib_metrics_match(struct fib_config *cfg, struct fib_info *fi)
{
    return false;
}

void rtmsg_fib(int event, __be32 key, struct fib_alias *fa, int dst_len,
        u32 tb_id, const struct nl_info *info, unsigned int nlm_flags)
{
}

void *kmemdup_noprof(const void *src, size_t len, gfp_t gfp)
{
    void *p = kmalloc(len, gfp);
    if (p)
        memcpy(p, src, len);
    return p;
}

char *strcat(char *dst, const char *src)
{
    char *ret = dst;
    while (*dst)
        dst++;
    while ((*dst++ = *src++))
        ;
    return ret;
}
