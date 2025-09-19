#include <linux/sched/mm.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/sched/signal.h>
#include <linux/sched/hotplug.h>
#include <linux/sched/isolation.h>
#include <linux/sched/task.h>
#include <linux/sched/smt.h>
#include <linux/unistd.h>
#include <linux/cpu.h>
#include <linux/oom.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/bug.h>
#include <linux/kthread.h>
#include <linux/stop_machine.h>
#include <linux/mutex.h>
#include <linux/gfp.h>
#include <linux/suspend.h>
#include <linux/lockdep.h>
#include <linux/tick.h>
#include <linux/irq.h>
#include <linux/nmi.h>
#include <linux/smpboot.h>
#include <linux/relay.h>
#include <linux/slab.h>
#include <linux/scs.h>
#include <linux/percpu-rwsem.h>
#include <linux/cpuset.h>
#include <linux/random.h>
#include <linux/cc_platform.h>

#include <trace/events/power.h>
#define CREATE_TRACE_POINTS
#include <trace/events/cpuhp.h>

#include "smpboot.h"
#include "../adaptor.h"

int __boot_cpu_id;

/*
 * If set, cpu_up and cpu_down will return -EBUSY and do nothing.
 * Should always be manipulated under cpu_add_remove_lock
 */
static int cpu_hotplug_disabled;

#ifdef CONFIG_INIT_ALL_POSSIBLE
struct cpumask __cpu_possible_mask __ro_after_init
    = {CPU_BITS_ALL};
#else
struct cpumask __cpu_possible_mask __ro_after_init;
#endif
struct cpumask __cpu_online_mask __read_mostly;
struct cpumask __cpu_enabled_mask __read_mostly;
struct cpumask __cpu_present_mask __read_mostly;
struct cpumask __cpu_active_mask __read_mostly;
struct cpumask __cpu_dying_mask __read_mostly;

atomic_t __num_online_cpus __read_mostly;

const DECLARE_BITMAP(cpu_all_bits, NR_CPUS) = CPU_BITS_ALL;

/* Serializes the updates to cpu_online_mask, cpu_present_mask */
static DEFINE_MUTEX(cpu_add_remove_lock);

/*
 * The following two APIs (cpu_maps_update_begin/done) must be used when
 * attempting to serialize the updates to cpu_online_mask & cpu_present_mask.
 */
void cpu_maps_update_begin(void)
{
    mutex_lock(&cpu_add_remove_lock);
}

void cpu_maps_update_done(void)
{
    mutex_unlock(&cpu_add_remove_lock);
}

int __cpuhp_state_add_instance(enum cpuhp_state state, struct hlist_node *node,
                   bool invoke)
{
#if 0
    int ret;

    cpus_read_lock();
    ret = __cpuhp_state_add_instance_cpuslocked(state, node, invoke);
    cpus_read_unlock();
    return ret;
#endif
    pr_notice("%s: No impl.", __func__);
}

int __cpuhp_setup_state(enum cpuhp_state state,
            const char *name, bool invoke,
            int (*startup)(unsigned int cpu),
            int (*teardown)(unsigned int cpu),
            bool multi_instance)
{
    pr_notice("%s: No impl.", __func__);

    if (startup) {
        startup(0);
    }
    return 0;

#if 0
    int ret;

    cpus_read_lock();
    ret = __cpuhp_setup_state_cpuslocked(state, name, invoke, startup,
                         teardown, multi_instance);
    cpus_read_unlock();
    return ret;
#endif
}

void set_cpu_online(unsigned int cpu, bool online)
{
    /*
     * atomic_inc/dec() is required to handle the horrid abuse of this
     * function by the reboot and kexec code which invoke it from
     * IPI/NMI broadcasts when shutting down CPUs. Invocation from
     * regular CPU hotplug is properly serialized.
     *
     * Note, that the fact that __num_online_cpus is of type atomic_t
     * does not protect readers which are not serialized against
     * concurrent hotplug operations.
     */
    if (online) {
        if (!cpumask_test_and_set_cpu(cpu, &__cpu_online_mask))
            atomic_inc(&__num_online_cpus);
    } else {
        if (cpumask_test_and_clear_cpu(cpu, &__cpu_online_mask))
            atomic_dec(&__num_online_cpus);
    }
}

void __cpuhp_remove_state(enum cpuhp_state state, bool invoke)
{
    pr_notice("%s: No impl.", __func__);
}

/*
 * Wait for currently running CPU hotplug operations to complete (if any) and
 * disable future CPU hotplug (from sysfs). The 'cpu_add_remove_lock' protects
 * the 'cpu_hotplug_disabled' flag. The same lock is also acquired by the
 * hotplug path before performing hotplug operations. So acquiring that lock
 * guarantees mutual exclusion from any currently running hotplug operations.
 */
void cpu_hotplug_disable(void)
{
    cpu_maps_update_begin();
    cpu_hotplug_disabled++;
    cpu_maps_update_done();
}

static void __cpu_hotplug_enable(void)
{
    if (WARN_ONCE(!cpu_hotplug_disabled, "Unbalanced cpu hotplug enable\n"))
        return;
    cpu_hotplug_disabled--;
}

void cpu_hotplug_enable(void)
{
    cpu_maps_update_begin();
    __cpu_hotplug_enable();
    cpu_maps_update_done();
}

/*
 * Activate the first processor.
 */
void __init boot_cpu_init(void)
{
    int cpu = smp_processor_id();

    /* Mark the boot cpu "present", "online" etc for SMP and UP case */
    set_cpu_online(cpu, true);
    set_cpu_active(cpu, true);
    set_cpu_present(cpu, true);
    set_cpu_possible(cpu, true);

#ifdef CONFIG_SMP
    __boot_cpu_id = cpu;
#endif
}
