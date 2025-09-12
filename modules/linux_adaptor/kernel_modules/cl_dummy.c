#include <linux/of.h>
#include <linux/cpumask_types.h>

#include <net/sock.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/sched/isolation.h>
#include <linux/swap.h>
#include <linux/task_work.h>

#include "../adaptor.h"

bool initcall_debug;

bool noirqdebug __read_mostly;

// defined in 'arch/riscv/mm/cacheflush.c'.
unsigned int riscv_cbom_block_size;

struct net init_net = {
    .ns.count = 1,
};

/*
 * cpu topology table
 */
struct cpu_topology cpu_topology[NR_CPUS];

#ifdef CONFIG_SPARSEMEM_VMEMMAP
#define VMEMMAP_ADDR_ALIGN  (1ULL << SECTION_SIZE_BITS)

unsigned long vmemmap_start_pfn __ro_after_init;
#endif

#ifdef CONFIG_64BIT
bool pgtable_l4_enabled __ro_after_init;
bool pgtable_l5_enabled __ro_after_init;
#endif

bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, unsigned int bit)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}

bool is_acpi_device_node(const struct fwnode_handle *fwnode)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}

bool is_software_node(const struct fwnode_handle *fwnode)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}

/**
 * is_swiotlb_allocated() - check if the default software IO TLB is initialized
 */
bool is_swiotlb_allocated(void)
{
    pr_notice("%s: No impl.", __func__);
    return false;
    //return io_tlb_default_mem.nslabs;
}

int sysfs_create_dir_ns(struct kobject *kobj, const void *ns)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int sysfs_create_groups(struct kobject *kobj,
            const struct attribute_group **groups)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

void kernfs_get(struct kernfs_node *kn)
{
    pr_notice("%s: No impl.", __func__);
}

void kernfs_put(struct kernfs_node *kn)
{
    pr_notice("%s: No impl.", __func__);
}

int kobject_uevent(struct kobject *kobj, enum kobject_action action)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

struct cpumask *group_cpus_evenly(unsigned int numgrps)
{
    pr_notice("%s: No impl.", __func__);
    static struct cpumask masks = {1};
    return &masks;
}

kuid_t make_kuid(struct user_namespace *ns, uid_t uid)
{
    pr_notice("%s: No impl.", __func__);
    return KUIDT_INIT(0);
}

kuid_t from_vfsuid(struct mnt_idmap *idmap,
           struct user_namespace *fs_userns, vfsuid_t vfsuid)
{
    pr_notice("%s: No impl.", __func__);
    return KUIDT_INIT(0);
}

kgid_t make_kgid(struct user_namespace *ns, gid_t gid)
{
    pr_notice("%s: No impl.", __func__);
    return KGIDT_INIT(0);
}

kgid_t from_vfsgid(struct mnt_idmap *idmap,
           struct user_namespace *fs_userns, vfsgid_t vfsgid)
{
    pr_notice("%s: No impl.", __func__);
    return KGIDT_INIT(0);
}

int blkcg_init_disk(struct gendisk *disk)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

/*
 * Find hart ID of the CPU DT node under which given DT node falls.
 *
 * To achieve this, we walk up the DT tree until we find an active
 * RISC-V core (HART) node and extract the cpuid from it.
 */
int riscv_of_parent_hartid(struct device_node *node, unsigned long *hartid)
{
    pr_notice("%s: No impl.", __func__);

    *hartid = 0;
    return 0;
}

bool housekeeping_test_cpu(int cpu, enum hk_type type)
{
    pr_notice("%s: No impl.", __func__);
    return true;
}

bool cpuset_cpu_is_isolated(int cpu)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}

int __srcu_read_lock(struct srcu_struct *ssp)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

void __srcu_read_unlock(struct srcu_struct *ssp, int idx)
{
    pr_notice("%s: No impl.", __func__);
}

void rcu_all_qs(void)
{
    pr_notice("%s: No impl.", __func__);
}

bool shmem_mapping(struct address_space *mapping)
{
    return false;
}

struct address_space *swapper_spaces[MAX_SWAPFILES] __read_mostly;

void mlock_drain_local(void)
{
    pr_notice("%s: No impl.", __func__);
}

int blocking_notifier_call_chain(struct blocking_notifier_head *nh,
        unsigned long val, void *v)
{
    pr_notice("%s: No impl.", __func__);
}

int task_work_add(struct task_struct *task, struct callback_head *work,
          enum task_work_notify_mode notify)
{
    pr_notice("%s: No impl.", __func__);
}

int blocking_notifier_chain_register(struct blocking_notifier_head *nh,
        struct notifier_block *n)
{
    pr_notice("%s: No impl.", __func__);
}

int blocking_notifier_chain_unregister(struct blocking_notifier_head *nh,
        struct notifier_block *n)
{
    pr_notice("%s: No impl.", __func__);
}

void percpu_counter_add_batch(struct percpu_counter *fbc, s64 amount, s32 batch)
{
    pr_notice("%s: No impl.", __func__);
}

bool set_freezable(void)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}

int set_task_ioprio(struct task_struct *task, int ioprio)
{
    pr_notice("%s: No impl.", __func__);
    //task->io_context->ioprio = ioprio;
    return 0;
}

time64_t ktime_get_real_seconds(void)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

unsigned long __msecs_to_jiffies(const unsigned int m)
{
    /*
     * Negative value, means infinite timeout:
     */
    if ((int)m < 0)
        return MAX_JIFFY_OFFSET;
    return _msecs_to_jiffies(m);
}

int sprint_symbol(char *buffer, unsigned long address)
{
    pr_notice("%s: [%s] addr[0x%lx]\n", __func__, buffer, address);
    return 0;
}

bool blk_cgroup_congested(void)
{
    return false;
}

unsigned long
__asm_copy_to_user(void __user *to, const void *from, unsigned long n)
{
    memcpy((void __force *)to, from, n);
}

int
send_sig(int sig, struct task_struct *p, int priv)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

const struct cpumask *housekeeping_cpumask(enum hk_type type)
{
    pr_notice("%s: No impl.", __func__);
    return cpu_possible_mask;
}

bool housekeeping_enabled(enum hk_type type)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}

void set_user_nice(struct task_struct *p, long nice)
{
    pr_notice("%s: No impl.", __func__);
    p->static_prio = NICE_TO_PRIO(nice);
}

void bio_associate_blkg_from_css(struct bio *bio,
                 struct cgroup_subsys_state *css)
{
    pr_notice("%s: No impl.", __func__);
}

/*
 * Zero means infinite timeout - no checking done:
 */
unsigned long __read_mostly sysctl_hung_task_timeout_secs = CONFIG_DEFAULT_HUNG_TASK_TIMEOUT;

int register_pm_notifier(struct notifier_block *nb)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_inode_init_security(struct inode *inode, struct inode *dir,
                 const struct qstr *qstr,
                 const initxattrs initxattrs, void *fs_data)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

void security_inode_post_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
                 int ia_valid)
{
    pr_notice("%s: No impl.", __func__);
}

int security_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_inode_create(struct inode *dir, struct dentry *dentry,
              umode_t mode)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int in_group_p(kgid_t grp)
{
    pr_notice("%s: No impl.", __func__);
    return 1;
}

bool capable(int cap)
{
    pr_notice("%s: No impl.", __func__);
    return true;
}

int fsnotify(__u32 mask, const void *data, int data_type, struct inode *dir,
         const struct qstr *file_name, struct inode *inode, u32 cookie)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

void __fsnotify_inode_delete(struct inode *inode)
{
    pr_notice("%s: No impl.", __func__);
}

void __audit_inode(struct filename *name, const struct dentry *dentry,
           unsigned int flags)
{
    pr_notice("%s: No impl.", __func__);
}

int security_inode_permission(struct inode *inode, int mask)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int devcgroup_check_permission(short type, u32 major, u32 minor, short access)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

/*
 * Notify this dentry's parent about a child's events with child name info
 * if parent is watching or if inode/sb/mount are interested in events with
 * parent and name info.
 *
 * Notify only the child without name info if parent is not watching and
 * inode/sb/mount are not interested in events with parent and name info.
 */
int __fsnotify_parent(struct dentry *dentry, __u32 mask, const void *data,
              int data_type)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

void dnotify_flush(struct file *filp, fl_owner_t id)
{
    pr_notice("%s: No impl.", __func__);
}

void eventpoll_release_file(struct file *file)
{
    pr_notice("%s: No impl.", __func__);
}

void security_file_release(struct file *file)
{
    pr_notice("%s: No impl.", __func__);
}

int security_path_mknod(const struct path *dir, struct dentry *dentry,
            umode_t mode, unsigned int dev)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_file_open(struct file *file)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_file_permission(struct file *file, int mask)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_file_post_open(struct file *file, int mask)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

void file_f_owner_release(struct file *file)
{
    pr_notice("%s: No impl.", __func__);
}

bool capable_wrt_inode_uidgid(struct mnt_idmap *idmap,
                  const struct inode *inode, int cap)
{
    pr_notice("%s: No impl.", __func__);
    return true;
}

void __audit_inode_child(struct inode *parent,
             const struct dentry *dentry,
             const unsigned char type)
{
    pr_notice("%s: No impl.", __func__);
}

int security_path_unlink(const struct path *dir, struct dentry *dentry)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_inode_getattr(const struct path *path)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_path_mkdir(const struct path *dir, struct dentry *dentry,
            umode_t mode)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_path_rmdir(const struct path *dir, struct dentry *dentry)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_path_truncate(const struct path *path)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int security_inode_setattr(struct mnt_idmap *idmap,
               struct dentry *dentry, struct iattr *attr)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

/*
 * __detach_mounts - lazily unmount all mounts on the specified dentry
 *
 * During unlink, rmdir, and d_drop it is possible to loose the path
 * to an existing mountpoint, and wind up leaking the mount.
 * detach_mounts allows lazily unmounting those mounts instead of
 * leaking them.
 *
 * The caller may hold dentry->d_inode->i_mutex.
 */
void __detach_mounts(struct dentry *dentry)
{
    pr_notice("%s: No impl.", __func__);
}

uid_t from_kuid_munged(struct user_namespace *targ, kuid_t kuid)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

gid_t from_kgid_munged(struct user_namespace *targ, kgid_t kgid)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

/**
 * tmigr_requires_handle_remote() - Check the need of remote timer handling
 *
 * Must be called with interrupts disabled.
 */
bool tmigr_requires_handle_remote(void)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}

void sysfs_notify(struct kobject *kobj, const char *dir, const char *attr)
{
    pr_notice("%s: No impl.", __func__);
}

/*
 * Generic 'turn off all lock debugging' function:
 */
int debug_locks_off(void)
{
    return 0;
}

int debug_locks_silent __read_mostly;

const u8 guid_index[16] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
const u8 uuid_index[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

void tracing_start_cmdline_record(void)
{
    pr_notice("%s: No impl.", __func__);
}

void lockdep_assert_cpus_held(void)
{
    pr_notice("%s: No impl.", __func__);
}

void cpus_read_lock(void)
{
    pr_notice("%s: No impl.", __func__);
}

void cpus_read_unlock(void)
{
    pr_notice("%s: No impl.", __func__);
}

void call_srcu(struct srcu_struct *ssp, struct rcu_head *rhp,
           rcu_callback_t func)
{
    pr_notice("%s: No impl.", __func__);
}

/*
 * For flush_icache_all.
 */
#include <linux/acpi.h>
#include <linux/of.h>
#include <linux/prctl.h>
#include <asm/acpi.h>
#include <asm/cacheflush.h>
#include <asm/sbi.h>

static void ipi_remote_fence_i(void *info)
{
    return local_flush_icache_all();
}

void flush_icache_all(void)
{
    local_flush_icache_all();

    if (num_online_cpus() < 2)
        return;

    /*
     * Make sure all previous writes to the D$ are ordered before making
     * the IPI. The RISC-V spec states that a hart must execute a data fence
     * before triggering a remote fence.i in order to make the modification
     * visable for remote harts.
     *
     * IPIs on RISC-V are triggered by MMIO writes to either CLINT or
     * S-IMSIC, so the fence ensures previous data writes "happen before"
     * the MMIO.
     */
    RISCV_FENCE(w, o);

#if 0
    if (riscv_use_sbi_for_rfence())
        sbi_remote_fence_i(NULL);
    else
        on_each_cpu(ipi_remote_fence_i, NULL, 1);
#endif
    sbi_remote_fence_i(NULL);
    pr_notice("%s: No impl.", __func__);
}

static int __sbi_rfence_v01(int fid, const struct cpumask *cpu_mask,
                unsigned long start, unsigned long size,
                unsigned long arg4, unsigned long arg5)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

/**
 * sbi_remote_fence_i() - Execute FENCE.I instruction on given remote harts.
 * @cpu_mask: A cpu mask containing all the target harts.
 *
 * Return: 0 on success, appropriate linux error code otherwise.
 */
int sbi_remote_fence_i(const struct cpumask *cpu_mask)
{
    return __sbi_rfence_v01(SBI_EXT_RFENCE_REMOTE_FENCE_I,
                cpu_mask, 0, 0, 0, 0);
}

/*
 * trace_clock_local(): the simplest and least coherent tracing clock.
 *
 * Useful for tracing that does not cross to other CPUs nor
 * does it go through idle events.
 */
u64 notrace trace_clock_local(void)
{
#if 0
    u64 clock;

    /*
     * sched_clock() is an architecture implemented, fast, scalable,
     * lockless clock. It is not guaranteed to be coherent across
     * CPUs, nor across CPU idle events.
     */
    preempt_disable_notrace();
    clock = sched_clock();
    preempt_enable_notrace();

    return clock;
#endif
    pr_notice("%s: No impl.", __func__);
    return 0;
}

long si_mem_available(void)
{
    pr_notice("%s: No impl.", __func__);
    return 0xFFFFFFFF;
}

int trace_create_savedcmd(void)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

unsigned long lpj_fine;

/* Note: we need time_init for it. */
unsigned long riscv_timebase __ro_after_init;

void trace_find_cmdline(int pid, char comm[])
{
    pr_notice("%s: No impl.", __func__);
}

notrace void touch_softlockup_watchdog(void)
{
    pr_notice("%s: No impl.", __func__);
}

struct logic_pio_hwaddr *find_io_range_by_fwnode(struct fwnode_handle *fwnode)
{
    pr_notice("%s: No impl.", __func__);
    return NULL;
}

bool acpi_driver_match_device(struct device *dev,
                  const struct device_driver *drv)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}

/*
 * Returns:
 *  0 on success, an iommu was configured
 *  -ENODEV if the device does not have any IOMMU
 *  -EPROBEDEFER if probing should be tried again
 *  -errno fatal errors
 */
int of_iommu_configure(struct device *dev, struct device_node *master_np,
               const u32 *id)
{
    pr_notice("%s: No impl.", __func__);
    return -ENODEV;
}

/**
 * iommu_device_use_default_domain() - Device driver wants to handle device
 *                                     DMA through the kernel DMA API.
 * @dev: The device.
 *
 * The device driver about to bind @dev wants to do DMA through the kernel
 * DMA API. Return 0 if it is allowed, otherwise an error.
 */
int iommu_device_use_default_domain(struct device *dev)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int of_clk_set_defaults(struct device_node *node, bool clk_supplier)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

int dev_pm_domain_attach(struct device *dev, bool power_on)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

void dev_pm_domain_detach(struct device *dev, bool power_off)
{
    pr_notice("%s: No impl.", __func__);
}

void iommu_device_unuse_default_domain(struct device *dev)
{
    pr_notice("%s: No impl.", __func__);
}

int devm_reset_controller_register(struct device *dev,
                   struct reset_controller_dev *rcdev)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

int __pm_runtime_resume(struct device *dev, int rpmflags)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

int __pm_runtime_idle(struct device *dev, int rpmflags)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}
