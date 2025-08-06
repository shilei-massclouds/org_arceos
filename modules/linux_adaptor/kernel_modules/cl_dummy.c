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

// Defined in arch/riscv/mm/dma-noncoherent.c
int dma_cache_alignment __ro_after_init = ARCH_DMA_MINALIGN;

bool initcall_debug;

bool noirqdebug __read_mostly;

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
    pr_err("%s: No impl.", __func__);
    return false;
}

bool is_acpi_device_node(const struct fwnode_handle *fwnode)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

bool is_software_node(const struct fwnode_handle *fwnode)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

/**
 * dump_stack_lvl - dump the current task information and its stack trace
 * @log_lvl: log level
 *
 * Architectures can override this implementation by implementing its own.
 */
asmlinkage __visible void dump_stack_lvl(const char *log_lvl)
{
    printk("%s", log_lvl);
}

/**
 * is_swiotlb_allocated() - check if the default software IO TLB is initialized
 */
bool is_swiotlb_allocated(void)
{
    pr_err("%s: No impl.", __func__);
    return false;
    //return io_tlb_default_mem.nslabs;
}

int sysfs_create_dir_ns(struct kobject *kobj, const void *ns)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

int sysfs_create_groups(struct kobject *kobj,
            const struct attribute_group **groups)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

void kernfs_get(struct kernfs_node *kn)
{
    pr_err("%s: No impl.", __func__);
}

void kernfs_put(struct kernfs_node *kn)
{
    pr_err("%s: No impl.", __func__);
}

int kobject_uevent(struct kobject *kobj, enum kobject_action action)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

struct cpumask *group_cpus_evenly(unsigned int numgrps)
{
    pr_err("%s: No impl.", __func__);
    static struct cpumask masks = {1};
    return &masks;
}

kuid_t make_kuid(struct user_namespace *ns, uid_t uid)
{
    return KUIDT_INIT(0);
}

kgid_t make_kgid(struct user_namespace *ns, gid_t gid)
{
    return KGIDT_INIT(0);
}

int blkcg_init_disk(struct gendisk *disk)
{
    pr_err("%s: No impl.", __func__);
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
    pr_err("%s: No impl.", __func__);

    *hartid = 0;
    return 0;
}

bool housekeeping_test_cpu(int cpu, enum hk_type type)
{
    pr_err("%s: No impl.", __func__);
    return true;
}

bool cpuset_cpu_is_isolated(int cpu)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

int __srcu_read_lock(struct srcu_struct *ssp)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

void __srcu_read_unlock(struct srcu_struct *ssp, int idx)
{
    pr_err("%s: No impl.", __func__);
}

void rcu_all_qs(void)
{
    pr_err("%s: No impl.", __func__);
}

bool shmem_mapping(struct address_space *mapping)
{
    return false;
}

struct address_space *swapper_spaces[MAX_SWAPFILES] __read_mostly;

void mlock_drain_local(void)
{
    pr_err("%s: No impl.", __func__);
}

int blocking_notifier_call_chain(struct blocking_notifier_head *nh,
        unsigned long val, void *v)
{
    pr_err("%s: No impl.", __func__);
}

int task_work_add(struct task_struct *task, struct callback_head *work,
          enum task_work_notify_mode notify)
{
    pr_err("%s: No impl.", __func__);
}

int blocking_notifier_chain_register(struct blocking_notifier_head *nh,
        struct notifier_block *n)
{
    pr_err("%s: No impl.", __func__);
}

int blocking_notifier_chain_unregister(struct blocking_notifier_head *nh,
        struct notifier_block *n)
{
    pr_err("%s: No impl.", __func__);
}

void percpu_counter_add_batch(struct percpu_counter *fbc, s64 amount, s32 batch)
{
    pr_err("%s: No impl.", __func__);
}

bool set_freezable(void)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

int set_task_ioprio(struct task_struct *task, int ioprio)
{
    pr_err("%s: No impl.", __func__);
    //task->io_context->ioprio = ioprio;
    return 0;
}

time64_t ktime_get_real_seconds(void)
{
    pr_err("%s: No impl.", __func__);
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
    pr_err("%s: [%s] addr[0x%lx]\n", __func__, buffer, address);
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
    pr_err("%s: No impl.", __func__);
    return 0;
}

const struct cpumask *housekeeping_cpumask(enum hk_type type)
{
    pr_err("%s: No impl.", __func__);
    return cpu_possible_mask;
}

bool housekeeping_enabled(enum hk_type type)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

void set_user_nice(struct task_struct *p, long nice)
{
    pr_err("%s: No impl.", __func__);
    p->static_prio = NICE_TO_PRIO(nice);
}

void bio_associate_blkg_from_css(struct bio *bio,
                 struct cgroup_subsys_state *css)
{
    pr_err("%s: No impl.", __func__);
}

/*
 * Zero means infinite timeout - no checking done:
 */
unsigned long __read_mostly sysctl_hung_task_timeout_secs = CONFIG_DEFAULT_HUNG_TASK_TIMEOUT;

int register_pm_notifier(struct notifier_block *nb)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

int security_inode_init_security(struct inode *inode, struct inode *dir,
                 const struct qstr *qstr,
                 const initxattrs initxattrs, void *fs_data)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

int in_group_p(kgid_t grp)
{
    pr_err("%s: No impl.", __func__);
    return 1;
}

bool capable(int cap)
{
    pr_err("%s: No impl.", __func__);
    return true;
}

int fsnotify(__u32 mask, const void *data, int data_type, struct inode *dir,
         const struct qstr *file_name, struct inode *inode, u32 cookie)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}
