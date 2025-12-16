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
#include "adaptor.h"

/**
 * struct cpuhp_cpu_state - Per cpu hotplug state storage
 * @state:  The current cpu state
 * @target: The target state
 * @fail:   Current CPU hotplug callback state
 * @thread: Pointer to the hotplug thread
 * @should_run: Thread should execute
 * @rollback:   Perform a rollback
 * @single: Single callback invocation
 * @bringup:    Single callback bringup or teardown selector
 * @node:   Remote CPU node; for multi-instance, do a
 *      single entry callback for install/remove
 * @last:   For multi-instance rollback, remember how far we got
 * @cb_state:   The state for a single callback (install/uninstall)
 * @result: Result of the operation
 * @ap_sync_state:  State for AP synchronization
 * @done_up:    Signal completion to the issuer of the task for cpu-up
 * @done_down:  Signal completion to the issuer of the task for cpu-down
 */
struct cpuhp_cpu_state {
    enum cpuhp_state    state;
    enum cpuhp_state    target;
    enum cpuhp_state    fail;
#ifdef CONFIG_SMP
    struct task_struct  *thread;
    bool            should_run;
    bool            rollback;
    bool            single;
    bool            bringup;
    struct hlist_node   *node;
    struct hlist_node   *last;
    enum cpuhp_state    cb_state;
    int         result;
    atomic_t        ap_sync_state;
    struct completion   done_up;
    struct completion   done_down;
#endif
};

static DEFINE_PER_CPU(struct cpuhp_cpu_state, cpuhp_state) = {
    .fail = CPUHP_INVALID,
};

/* Synchronization state management */
enum cpuhp_sync_state {
    SYNC_STATE_DEAD,
    SYNC_STATE_KICKED,
    SYNC_STATE_SHOULD_DIE,
    SYNC_STATE_ALIVE,
    SYNC_STATE_SHOULD_ONLINE,
    SYNC_STATE_ONLINE,
};

cpumask_t cpus_booted_once_mask;

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
 * cpu_bit_bitmap[] is a special, "compressed" data structure that
 * represents all NR_CPUS bits binary values of 1<<nr.
 *
 * It is used by cpumask_of() to get a constant address to a CPU
 * mask value that has a single bit set only.
 */

/* cpu_bit_bitmap[0] is empty - so we can back into it */
#define MASK_DECLARE_1(x)   [x+1][0] = (1UL << (x))
#define MASK_DECLARE_2(x)   MASK_DECLARE_1(x), MASK_DECLARE_1(x+1)
#define MASK_DECLARE_4(x)   MASK_DECLARE_2(x), MASK_DECLARE_2(x+2)
#define MASK_DECLARE_8(x)   MASK_DECLARE_4(x), MASK_DECLARE_4(x+4)

const unsigned long cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)] = {

    MASK_DECLARE_8(0),  MASK_DECLARE_8(8),
    MASK_DECLARE_8(16), MASK_DECLARE_8(24),
#if BITS_PER_LONG > 32
    MASK_DECLARE_8(32), MASK_DECLARE_8(40),
    MASK_DECLARE_8(48), MASK_DECLARE_8(56),
#endif
};

/**
 * struct cpuhp_step - Hotplug state machine step
 * @name:   Name of the step
 * @startup:    Startup function of the step
 * @teardown:   Teardown function of the step
 * @cant_stop:  Bringup/teardown can't be stopped at this step
 * @multi_instance: State has multiple instances which get added afterwards
 */
struct cpuhp_step {
    const char      *name;
    union {
        int     (*single)(unsigned int cpu);
        int     (*multi)(unsigned int cpu,
                     struct hlist_node *node);
    } startup;
    union {
        int     (*single)(unsigned int cpu);
        int     (*multi)(unsigned int cpu,
                     struct hlist_node *node);
    } teardown;
    /* private: */
    struct hlist_head   list;
    /* public: */
    bool            cant_stop;
    bool            multi_instance;
};

static DEFINE_MUTEX(cpuhp_state_mutex);
static struct cpuhp_step cpuhp_hp_states[];

DEFINE_STATIC_PERCPU_RWSEM(cpu_hotplug_lock);

bool cpuhp_tasks_frozen;

/*
 * Architectures that need SMT-specific errata handling during SMT hotplug
 * should override this.
 */
void __weak arch_smt_update(void) { }

static struct cpuhp_step *cpuhp_get_step(enum cpuhp_state state)
{
    return cpuhp_hp_states + state;
}

static bool cpuhp_step_empty(bool bringup, struct cpuhp_step *step)
{
    return bringup ? !step->startup.single : !step->teardown.single;
}

/**
 * cpuhp_invoke_callback - Invoke the callbacks for a given state
 * @cpu:    The cpu for which the callback should be invoked
 * @state:  The state to do callbacks for
 * @bringup:    True if the bringup callback should be invoked
 * @node:   For multi-instance, do a single entry callback for install/remove
 * @lastp:  For multi-instance rollback, remember how far we got
 *
 * Called from cpu hotplug and from the state register machinery.
 *
 * Return: %0 on success or a negative errno code
 */
static int cpuhp_invoke_callback(unsigned int cpu, enum cpuhp_state state,
                 bool bringup, struct hlist_node *node,
                 struct hlist_node **lastp)
{
    struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
    struct cpuhp_step *step = cpuhp_get_step(state);
    int (*cbm)(unsigned int cpu, struct hlist_node *node);
    int (*cb)(unsigned int cpu);
    int ret, cnt;

    if (st->fail == state) {
        st->fail = CPUHP_INVALID;
        return -EAGAIN;
    }

    if (cpuhp_step_empty(bringup, step)) {
        WARN_ON_ONCE(1);
        return 0;
    }

    if (!step->multi_instance) {
        WARN_ON_ONCE(lastp && *lastp);
        cb = bringup ? step->startup.single : step->teardown.single;

        trace_cpuhp_enter(cpu, st->target, state, cb);
        ret = cb(cpu);
        trace_cpuhp_exit(cpu, st->state, state, ret);
        return ret;
    }
    cbm = bringup ? step->startup.multi : step->teardown.multi;

    /* Single invocation for instance add/remove */
    if (node) {
        WARN_ON_ONCE(lastp && *lastp);
        trace_cpuhp_multi_enter(cpu, st->target, state, cbm, node);
        ret = cbm(cpu, node);
        trace_cpuhp_exit(cpu, st->state, state, ret);
        return ret;
    }

    /* State transition. Invoke on all instances */
    cnt = 0;
    hlist_for_each(node, &step->list) {
        if (lastp && node == *lastp)
            break;

        trace_cpuhp_multi_enter(cpu, st->target, state, cbm, node);
        ret = cbm(cpu, node);
        trace_cpuhp_exit(cpu, st->state, state, ret);
        if (ret) {
            if (!lastp)
                goto err;

            *lastp = node;
            return ret;
        }
        cnt++;
    }
    if (lastp)
        *lastp = NULL;
    return 0;
err:
    /* Rollback the instances if one failed */
    cbm = !bringup ? step->startup.multi : step->teardown.multi;
    if (!cbm)
        return ret;

    hlist_for_each(node, &step->list) {
        if (!cnt--)
            break;

        trace_cpuhp_multi_enter(cpu, st->target, state, cbm, node);
        ret = cbm(cpu, node);
        trace_cpuhp_exit(cpu, st->state, state, ret);
        /*
         * Rollback must not fail,
         */
        WARN_ON_ONCE(ret);
    }
    PANIC("");
    return ret;
}

void cpus_write_lock(void)
{
    percpu_down_write(&cpu_hotplug_lock);
}

void cpus_write_unlock(void)
{
    percpu_up_write(&cpu_hotplug_lock);
}

static int bringup_cpu(unsigned int cpu)
{
    struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
    struct task_struct *idle = idle_thread_get(cpu);
    int ret;

#if 0
    if (!cpuhp_can_boot_ap(cpu))
        return -EAGAIN;

    /*
     * Some architectures have to walk the irq descriptors to
     * setup the vector space for the cpu which comes online.
     *
     * Prevent irq alloc/free across the bringup by acquiring the
     * sparse irq lock. Hold it until the upcoming CPU completes the
     * startup in cpuhp_online_idle() which allows to avoid
     * intermediate synchronization points in the architecture code.
     */
    irq_lock_sparse();

    ret = __cpu_up(cpu, idle);
    if (ret)
        goto out_unlock;

    ret = cpuhp_bp_sync_alive(cpu);
    if (ret)
        goto out_unlock;

    ret = bringup_wait_for_ap_online(cpu);
    if (ret)
        goto out_unlock;

    irq_unlock_sparse();

    if (st->target <= CPUHP_AP_ONLINE_IDLE)
        return 0;

    return cpuhp_kick_ap(cpu, st, st->target);

out_unlock:
    irq_unlock_sparse();
    return ret;
#endif
    PANIC("");
}

static int finish_cpu(unsigned int cpu)
{
    struct task_struct *idle = idle_thread_get(cpu);
    struct mm_struct *mm = idle->active_mm;

    /*
     * idle_task_exit() will have switched to &init_mm, now
     * clean up any remaining active_mm state.
     */
    if (mm != &init_mm)
        idle->active_mm = &init_mm;
    mmdrop_lazy_tlb(mm);
    return 0;
}

static int takedown_cpu(unsigned int cpu)
{
    PANIC("");
}

/* Boot processor state steps */
static struct cpuhp_step cpuhp_hp_states[] = {
    [CPUHP_OFFLINE] = {
        .name           = "offline",
        .startup.single     = NULL,
        .teardown.single    = NULL,
    },
#ifdef CONFIG_SMP
    [CPUHP_CREATE_THREADS]= {
        .name           = "threads:prepare",
        .startup.single     = smpboot_create_threads,
        .teardown.single    = NULL,
        .cant_stop      = true,
    },
    [CPUHP_PERF_PREPARE] = {
        .name           = "perf:prepare",
        .startup.single     = perf_event_init_cpu,
        .teardown.single    = perf_event_exit_cpu,
    },
    [CPUHP_RANDOM_PREPARE] = {
        .name           = "random:prepare",
        .startup.single     = random_prepare_cpu,
        .teardown.single    = NULL,
    },
    [CPUHP_WORKQUEUE_PREP] = {
        .name           = "workqueue:prepare",
        .startup.single     = workqueue_prepare_cpu,
        .teardown.single    = NULL,
    },
    [CPUHP_HRTIMERS_PREPARE] = {
        .name           = "hrtimers:prepare",
        .startup.single     = hrtimers_prepare_cpu,
        .teardown.single    = NULL,
    },
    [CPUHP_SMPCFD_PREPARE] = {
        .name           = "smpcfd:prepare",
        .startup.single     = smpcfd_prepare_cpu,
        .teardown.single    = smpcfd_dead_cpu,
    },
    [CPUHP_RELAY_PREPARE] = {
        .name           = "relay:prepare",
        .startup.single     = relay_prepare_cpu,
        .teardown.single    = NULL,
    },
    [CPUHP_RCUTREE_PREP] = {
        .name           = "RCU/tree:prepare",
        .startup.single     = rcutree_prepare_cpu,
        .teardown.single    = rcutree_dead_cpu,
    },
    /*
     * On the tear-down path, timers_dead_cpu() must be invoked
     * before blk_mq_queue_reinit_notify() from notify_dead(),
     * otherwise a RCU stall occurs.
     */
    [CPUHP_TIMERS_PREPARE] = {
        .name           = "timers:prepare",
        .startup.single     = timers_prepare_cpu,
        .teardown.single    = timers_dead_cpu,
    },

#ifdef CONFIG_HOTPLUG_SPLIT_STARTUP
    /*
     * Kicks the AP alive. AP will wait in cpuhp_ap_sync_alive() until
     * the next step will release it.
     */
    [CPUHP_BP_KICK_AP] = {
        .name           = "cpu:kick_ap",
        .startup.single     = cpuhp_kick_ap_alive,
    },

    /*
     * Waits for the AP to reach cpuhp_ap_sync_alive() and then
     * releases it for the complete bringup.
     */
    [CPUHP_BRINGUP_CPU] = {
        .name           = "cpu:bringup",
        .startup.single     = cpuhp_bringup_ap,
        .teardown.single    = finish_cpu,
        .cant_stop      = true,
    },
#else
    /*
     * All-in-one CPU bringup state which includes the kick alive.
     */
    [CPUHP_BRINGUP_CPU] = {
        .name           = "cpu:bringup",
        .startup.single     = bringup_cpu,
        .teardown.single    = finish_cpu,
        .cant_stop      = true,
    },
#endif
    /* Final state before CPU kills itself */
    [CPUHP_AP_IDLE_DEAD] = {
        .name           = "idle:dead",
    },
    /*
     * Last state before CPU enters the idle loop to die. Transient state
     * for synchronization.
     */
    [CPUHP_AP_OFFLINE] = {
        .name           = "ap:offline",
        .cant_stop      = true,
    },
    /* First state is scheduler control. Interrupts are disabled */
    [CPUHP_AP_SCHED_STARTING] = {
        .name           = "sched:starting",
        .startup.single     = sched_cpu_starting,
        .teardown.single    = sched_cpu_dying,
    },
    [CPUHP_AP_RCUTREE_DYING] = {
        .name           = "RCU/tree:dying",
        .startup.single     = NULL,
        .teardown.single    = rcutree_dying_cpu,
    },
    [CPUHP_AP_SMPCFD_DYING] = {
        .name           = "smpcfd:dying",
        .startup.single     = NULL,
        .teardown.single    = smpcfd_dying_cpu,
    },
    [CPUHP_AP_HRTIMERS_DYING] = {
        .name           = "hrtimers:dying",
        .startup.single     = hrtimers_cpu_starting,
        .teardown.single    = hrtimers_cpu_dying,
    },
    [CPUHP_AP_TICK_DYING] = {
        .name           = "tick:dying",
        .startup.single     = NULL,
        .teardown.single    = tick_cpu_dying,
    },
    /* Entry state on starting. Interrupts enabled from here on. Transient
     * state for synchronsization */
    [CPUHP_AP_ONLINE] = {
        .name           = "ap:online",
    },
    /*
     * Handled on control processor until the plugged processor manages
     * this itself.
     */
    [CPUHP_TEARDOWN_CPU] = {
        .name           = "cpu:teardown",
        .startup.single     = NULL,
        .teardown.single    = takedown_cpu,
        .cant_stop      = true,
    },

    [CPUHP_AP_SCHED_WAIT_EMPTY] = {
        .name           = "sched:waitempty",
        .startup.single     = NULL,
        .teardown.single    = sched_cpu_wait_empty,
    },

    /* Handle smpboot threads park/unpark */
    [CPUHP_AP_SMPBOOT_THREADS] = {
        .name           = "smpboot/threads:online",
        .startup.single     = smpboot_unpark_threads,
        .teardown.single    = smpboot_park_threads,
    },
    [CPUHP_AP_IRQ_AFFINITY_ONLINE] = {
        .name           = "irq/affinity:online",
        .startup.single     = irq_affinity_online_cpu,
        .teardown.single    = NULL,
    },
    [CPUHP_AP_PERF_ONLINE] = {
        .name           = "perf:online",
        .startup.single     = perf_event_init_cpu,
        .teardown.single    = perf_event_exit_cpu,
    },
    [CPUHP_AP_WATCHDOG_ONLINE] = {
        .name           = "lockup_detector:online",
        .startup.single     = lockup_detector_online_cpu,
        .teardown.single    = lockup_detector_offline_cpu,
    },
    [CPUHP_AP_WORKQUEUE_ONLINE] = {
        .name           = "workqueue:online",
        .startup.single     = workqueue_online_cpu,
        .teardown.single    = workqueue_offline_cpu,
    },
    [CPUHP_AP_RANDOM_ONLINE] = {
        .name           = "random:online",
        .startup.single     = random_online_cpu,
        .teardown.single    = NULL,
    },
    [CPUHP_AP_RCUTREE_ONLINE] = {
        .name           = "RCU/tree:online",
        .startup.single     = rcutree_online_cpu,
        .teardown.single    = rcutree_offline_cpu,
    },
#endif
    /*
     * The dynamically registered state space is here
     */

#ifdef CONFIG_SMP
    /* Last state is scheduler control setting the cpu active */
    [CPUHP_AP_ACTIVE] = {
        .name           = "sched:active",
        .startup.single     = sched_cpu_activate,
        .teardown.single    = sched_cpu_deactivate,
    },
#endif

    /* CPU is fully up and running. */
    [CPUHP_ONLINE] = {
        .name           = "online",
        .startup.single     = NULL,
        .teardown.single    = NULL,
    },
};

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

/* Sanity check for callbacks */
static int cpuhp_cb_check(enum cpuhp_state state)
{
    if (state <= CPUHP_OFFLINE || state >= CPUHP_ONLINE)
        return -EINVAL;
    return 0;
}

static bool cpuhp_is_ap_state(enum cpuhp_state state)
{
    /*
     * The extra check for CPUHP_TEARDOWN_CPU is only for documentation
     * purposes as that state is handled explicitly in cpu_down.
     */
    return state > CPUHP_BRINGUP_CPU && state != CPUHP_TEARDOWN_CPU;
}

static inline void cpuhp_lock_acquire(bool bringup) { }
static inline void cpuhp_lock_release(bool bringup) { }

/* Regular hotplug invocation of the AP hotplug thread */
static void __cpuhp_kick_ap(struct cpuhp_cpu_state *st)
{
    if (!st->single && st->state == st->target)
        return;

#if 0
    st->result = 0;
    /*
     * Make sure the above stores are visible before should_run becomes
     * true. Paired with the mb() above in cpuhp_thread_fun()
     */
    smp_mb();
    st->should_run = true;
    wake_up_process(st->thread);
    wait_for_ap_thread(st, st->bringup);
#endif
    PANIC("");
}

/* Invoke a single callback on a remote cpu */
static int
cpuhp_invoke_ap_callback(int cpu, enum cpuhp_state state, bool bringup,
             struct hlist_node *node)
{
    struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
    int ret;

    if (!cpu_online(cpu))
        return 0;

    cpuhp_lock_acquire(false);
    cpuhp_lock_release(false);

    cpuhp_lock_acquire(true);
    cpuhp_lock_release(true);

    /*
     * If we are up and running, use the hotplug thread. For early calls
     * we invoke the thread function directly.
     */
    if (!st->thread)
        return cpuhp_invoke_callback(cpu, state, bringup, node, NULL);

    st->rollback = false;
    st->last = NULL;

    st->node = node;
    st->bringup = bringup;
    st->cb_state = state;
    st->single = true;

    __cpuhp_kick_ap(st);

    /*
     * If we failed and did a partial, do a rollback.
     */
    if ((ret = st->result) && st->last) {
        st->rollback = true;
        st->bringup = !bringup;

        __cpuhp_kick_ap(st);
    }

    /*
     * Clean up the leftovers so the next hotplug operation wont use stale
     * data.
     */
    st->node = st->last = NULL;
    PANIC("");
    return ret;
}

/*
 * Call the startup/teardown function for a step either on the AP or
 * on the current CPU.
 */
static int cpuhp_issue_call(int cpu, enum cpuhp_state state, bool bringup,
                struct hlist_node *node)
{
    struct cpuhp_step *sp = cpuhp_get_step(state);
    int ret;

    /*
     * If there's nothing to do, we done.
     * Relies on the union for multi_instance.
     */
    if (cpuhp_step_empty(bringup, sp))
        return 0;
    /*
     * The non AP bound callbacks can fail on bringup. On teardown
     * e.g. module removal we crash for now.
     */
#ifdef CONFIG_SMP
    if (cpuhp_is_ap_state(state))
        ret = cpuhp_invoke_ap_callback(cpu, state, bringup, node);
    else
        ret = cpuhp_invoke_callback(cpu, state, bringup, node, NULL);
#else
    ret = cpuhp_invoke_callback(cpu, state, bringup, node, NULL);
#endif
    BUG_ON(ret && !bringup);
    return ret;
}

/*
 * Called from __cpuhp_setup_state on a recoverable failure.
 *
 * Note: The teardown callbacks for rollback are not allowed to fail!
 */
static void cpuhp_rollback_install(int failedcpu, enum cpuhp_state state,
                   struct hlist_node *node)
{
    int cpu;

    /* Roll back the already executed steps on the other cpus */
    for_each_present_cpu(cpu) {
        struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
        int cpustate = st->state;

        if (cpu >= failedcpu)
            break;

        /* Did we invoke the startup call on that cpu ? */
        if (cpustate >= state)
            cpuhp_issue_call(cpu, state, false, node);
    }
}

int __cpuhp_state_add_instance_cpuslocked(enum cpuhp_state state,
                      struct hlist_node *node,
                      bool invoke)
{
    struct cpuhp_step *sp;
    int cpu;
    int ret;

    lockdep_assert_cpus_held();

    sp = cpuhp_get_step(state);
    if (sp->multi_instance == false)
        return -EINVAL;

    mutex_lock(&cpuhp_state_mutex);

    if (!invoke || !sp->startup.multi)
        goto add_node;

    /*
     * Try to call the startup callback for each present cpu
     * depending on the hotplug state of the cpu.
     */
    for_each_present_cpu(cpu) {
        struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
        int cpustate = st->state;

        if (cpustate < state)
            continue;

        ret = cpuhp_issue_call(cpu, state, true, node);
        if (ret) {
            if (sp->teardown.multi)
                cpuhp_rollback_install(cpu, state, node);
            goto unlock;
        }
    }
add_node:
    ret = 0;
    hlist_add_head(node, &sp->list);
unlock:
    mutex_unlock(&cpuhp_state_mutex);
    return ret;
}

int __cpuhp_state_add_instance(enum cpuhp_state state, struct hlist_node *node,
                   bool invoke)
{
    int ret;

    cpus_read_lock();
    ret = __cpuhp_state_add_instance_cpuslocked(state, node, invoke);
    cpus_read_unlock();
    return ret;
}

/*
 * Returns a free for dynamic slot assignment of the Online state. The states
 * are protected by the cpuhp_slot_states mutex and an empty slot is identified
 * by having no name assigned.
 */
static int cpuhp_reserve_state(enum cpuhp_state state)
{
    enum cpuhp_state i, end;
    struct cpuhp_step *step;

    switch (state) {
    case CPUHP_AP_ONLINE_DYN:
        step = cpuhp_hp_states + CPUHP_AP_ONLINE_DYN;
        end = CPUHP_AP_ONLINE_DYN_END;
        break;
    case CPUHP_BP_PREPARE_DYN:
        step = cpuhp_hp_states + CPUHP_BP_PREPARE_DYN;
        end = CPUHP_BP_PREPARE_DYN_END;
        break;
    default:
        return -EINVAL;
    }

    for (i = state; i <= end; i++, step++) {
        if (!step->name)
            return i;
    }
    WARN(1, "No more dynamic states available for CPU hotplug\n");
    return -ENOSPC;
}

static int cpuhp_store_callbacks(enum cpuhp_state state, const char *name,
                 int (*startup)(unsigned int cpu),
                 int (*teardown)(unsigned int cpu),
                 bool multi_instance)
{
    /* (Un)Install the callbacks for further cpu hotplug operations */
    struct cpuhp_step *sp;
    int ret = 0;

    /*
     * If name is NULL, then the state gets removed.
     *
     * CPUHP_AP_ONLINE_DYN and CPUHP_BP_PREPARE_DYN are handed out on
     * the first allocation from these dynamic ranges, so the removal
     * would trigger a new allocation and clear the wrong (already
     * empty) state, leaving the callbacks of the to be cleared state
     * dangling, which causes wreckage on the next hotplug operation.
     */
    if (name && (state == CPUHP_AP_ONLINE_DYN ||
             state == CPUHP_BP_PREPARE_DYN)) {
        ret = cpuhp_reserve_state(state);
        if (ret < 0)
            return ret;
        state = ret;
    }
    sp = cpuhp_get_step(state);
    if (name && sp->name)
        return -EBUSY;

    sp->startup.single = startup;
    sp->teardown.single = teardown;
    sp->name = name;
    sp->multi_instance = multi_instance;
    INIT_HLIST_HEAD(&sp->list);
    return ret;
}

/**
 * __cpuhp_setup_state_cpuslocked - Setup the callbacks for an hotplug machine state
 * @state:      The state to setup
 * @name:       Name of the step
 * @invoke:     If true, the startup function is invoked for cpus where
 *          cpu state >= @state
 * @startup:        startup callback function
 * @teardown:       teardown callback function
 * @multi_instance: State is set up for multiple instances which get
 *          added afterwards.
 *
 * The caller needs to hold cpus read locked while calling this function.
 * Return:
 *   On success:
 *      Positive state number if @state is CPUHP_AP_ONLINE_DYN or CPUHP_BP_PREPARE_DYN;
 *      0 for all other states
 *   On failure: proper (negative) error code
 */
int __cpuhp_setup_state_cpuslocked(enum cpuhp_state state,
                   const char *name, bool invoke,
                   int (*startup)(unsigned int cpu),
                   int (*teardown)(unsigned int cpu),
                   bool multi_instance)
{
    int cpu, ret = 0;
    bool dynstate;

    lockdep_assert_cpus_held();

    if (cpuhp_cb_check(state) || !name)
        return -EINVAL;

    mutex_lock(&cpuhp_state_mutex);

    ret = cpuhp_store_callbacks(state, name, startup, teardown,
                    multi_instance);

    dynstate = state == CPUHP_AP_ONLINE_DYN || state == CPUHP_BP_PREPARE_DYN;
    if (ret > 0 && dynstate) {
        state = ret;
        ret = 0;
    }

    printk("%s: step1\n", __func__);

    if (ret || !invoke || !startup)
        goto out;

    /*
     * Try to call the startup callback for each present cpu
     * depending on the hotplug state of the cpu.
     */
    for_each_present_cpu(cpu) {
        struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
        int cpustate = st->state;

        printk("++++++++ %s: cpu(%u) cpustate(%d) state(%u)\n", __func__, cpu, cpustate, state);
        if (cpustate < state)
            continue;

        ret = cpuhp_issue_call(cpu, state, true, NULL);
        if (ret) {
            if (teardown)
                cpuhp_rollback_install(cpu, state, NULL);
            cpuhp_store_callbacks(state, NULL, NULL, NULL, false);
            goto out;
        }
    }
out:
    mutex_unlock(&cpuhp_state_mutex);
    /*
     * If the requested state is CPUHP_AP_ONLINE_DYN or CPUHP_BP_PREPARE_DYN,
     * return the dynamically allocated state in case of success.
     */
    if (!ret && dynstate)
        return state;
    return ret;
}

int __cpuhp_setup_state(enum cpuhp_state state,
            const char *name, bool invoke,
            int (*startup)(unsigned int cpu),
            int (*teardown)(unsigned int cpu),
            bool multi_instance)
{
    int ret;

    cpus_read_lock();
    ret = __cpuhp_setup_state_cpuslocked(state, name, invoke, startup,
                         teardown, multi_instance);
    cpus_read_unlock();
    return ret;
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
    PANIC("");
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
    printk("%s: cpu_hotplug_disabled(%d)\n", __func__, cpu_hotplug_disabled);
    cpu_maps_update_begin();
    cpu_hotplug_disabled++;
    cpu_maps_update_done();
}

static void __cpu_hotplug_enable(void)
{
    printk("%s: cpu_hotplug_disabled(%d)\n", __func__, cpu_hotplug_disabled);
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

static inline bool cpu_bootable(unsigned int cpu) { return true; }

static inline enum cpuhp_state
cpuhp_set_state(int cpu, struct cpuhp_cpu_state *st, enum cpuhp_state target)
{
    enum cpuhp_state prev_state = st->state;
    bool bringup = st->state < target;

    st->rollback = false;
    st->last = NULL;

    st->target = target;
    st->single = false;
    st->bringup = bringup;
    if (cpu_dying(cpu) != !bringup)
        set_cpu_dying(cpu, !bringup);

    return prev_state;
}

static int cpuhp_kick_ap_work(unsigned int cpu)
{
    PANIC("");
}

/*
 * Get the next state to run. Empty ones will be skipped. Returns true if a
 * state must be run.
 *
 * st->state will be modified ahead of time, to match state_to_run, as if it
 * has already ran.
 */
static bool cpuhp_next_state(bool bringup,
                 enum cpuhp_state *state_to_run,
                 struct cpuhp_cpu_state *st,
                 enum cpuhp_state target)
{
    do {
        if (bringup) {
            if (st->state >= target)
                return false;

            *state_to_run = ++st->state;
        } else {
            if (st->state <= target)
                return false;

            *state_to_run = st->state--;
        }

        if (!cpuhp_step_empty(bringup, cpuhp_get_step(*state_to_run)))
            break;
    } while (true);

    return true;
}

static int __cpuhp_invoke_callback_range(bool bringup,
                     unsigned int cpu,
                     struct cpuhp_cpu_state *st,
                     enum cpuhp_state target,
                     bool nofail)
{
    enum cpuhp_state state;
    int ret = 0;

    while (cpuhp_next_state(bringup, &state, st, target)) {
        int err;

        err = cpuhp_invoke_callback(cpu, state, bringup, NULL, NULL);
        if (!err)
            continue;

        if (nofail) {
            pr_warn("CPU %u %s state %s (%d) failed (%d)\n",
                cpu, bringup ? "UP" : "DOWN",
                cpuhp_get_step(st->state)->name,
                st->state, err);
            ret = -1;
        } else {
            ret = err;
            break;
        }
    }

    return ret;
}

static inline int cpuhp_invoke_callback_range(bool bringup,
                          unsigned int cpu,
                          struct cpuhp_cpu_state *st,
                          enum cpuhp_state target)
{
    printk("%s: cpu(%u) bringup(%d)\n", __func__, cpu, bringup);
    return __cpuhp_invoke_callback_range(bringup, cpu, st, target, false);
}

static inline bool can_rollback_cpu(struct cpuhp_cpu_state *st)
{
    if (IS_ENABLED(CONFIG_HOTPLUG_CPU))
        return true;
    /*
     * When CPU hotplug is disabled, then taking the CPU down is not
     * possible because takedown_cpu() and the architecture and
     * subsystem specific mechanisms are not available. So the CPU
     * which would be completely unplugged again needs to stay around
     * in the current state.
     */
    return st->state <= CPUHP_BRINGUP_CPU;
}

static inline void
cpuhp_reset_state(int cpu, struct cpuhp_cpu_state *st,
          enum cpuhp_state prev_state)
{
    bool bringup = !st->bringup;

    st->target = prev_state;

    /*
     * Already rolling back. No need invert the bringup value or to change
     * the current state.
     */
    if (st->rollback)
        return;

    st->rollback = true;

    /*
     * If we have st->last we need to undo partial multi_instance of this
     * state first. Otherwise start undo at the previous state.
     */
    if (!st->last) {
        if (st->bringup)
            st->state--;
        else
            st->state++;
    }

    st->bringup = bringup;
    if (cpu_dying(cpu) != !bringup)
        set_cpu_dying(cpu, !bringup);
}

static int cpuhp_up_callbacks(unsigned int cpu, struct cpuhp_cpu_state *st,
                  enum cpuhp_state target)
{
    enum cpuhp_state prev_state = st->state;
    int ret = 0;

    printk("%s: state(%d) target(%d)\n", __func__, st->state, target);
    ret = cpuhp_invoke_callback_range(true, cpu, st, target);
    if (ret) {
        pr_debug("CPU UP failed (%d) CPU %u state %s (%d)\n",
             ret, cpu, cpuhp_get_step(st->state)->name,
             st->state);

        cpuhp_reset_state(cpu, st, prev_state);
        if (can_rollback_cpu(st))
            WARN_ON(cpuhp_invoke_callback_range(false, cpu, st,
                                prev_state));
    }
    return ret;
}

/* Requires cpu_add_remove_lock to be held */
static int _cpu_up(unsigned int cpu, int tasks_frozen, enum cpuhp_state target)
{
    struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
    struct task_struct *idle;
    int ret = 0;

    cpus_write_lock();

    if (!cpu_present(cpu)) {
        ret = -EINVAL;
        goto out;
    }

    /*
     * The caller of cpu_up() might have raced with another
     * caller. Nothing to do.
     */
    if (st->state >= target)
        goto out;

    if (st->state == CPUHP_OFFLINE) {
    printk("%s: step1 (%u)(%u)\n", __func__, st->state, target);
        /* Let it fail before we try to bring the cpu up */
        idle = idle_thread_get(cpu);
        if (IS_ERR(idle)) {
            ret = PTR_ERR(idle);
            goto out;
        }
    printk("%s: step2\n", __func__);

        /*
         * Reset stale stack state from the last time this CPU was online.
         */
        scs_task_reset(idle);
        kasan_unpoison_task_stack(idle);
    }

    printk("%s: step3\n", __func__);
    cpuhp_tasks_frozen = tasks_frozen;

    cpuhp_set_state(cpu, st, target);
    /*
     * If the current CPU state is in the range of the AP hotplug thread,
     * then we need to kick the thread once more.
     */
    if (st->state > CPUHP_BRINGUP_CPU) {
        ret = cpuhp_kick_ap_work(cpu);
        /*
         * The AP side has done the error rollback already. Just
         * return the error code..
         */
        if (ret)
            goto out;
    }

    /*
     * Try to reach the target state. We max out on the BP at
     * CPUHP_BRINGUP_CPU. After that the AP hotplug thread is
     * responsible for bringing it up to the target state.
     */
    target = min((int)target, CPUHP_BRINGUP_CPU);

#if 0
    //
    // Note: fix it!
    // Now we just use CPUHP_ONLINE rather than CPUHP_BRINGUP_CPU
    // Because we don't want to use hotplug-kthreads.
    //
    target = min((int)target, CPUHP_ONLINE);
#endif

    ret = cpuhp_up_callbacks(cpu, st, target);
out:
    cpus_write_unlock();
    arch_smt_update();
    return ret;
}

static int cpu_up(unsigned int cpu, enum cpuhp_state target)
{
    int err = 0;

    if (!cpu_possible(cpu)) {
        pr_err("can't online cpu %d because it is not configured as may-hotadd at boot time\n",
               cpu);
        return -EINVAL;
    }

    err = try_online_node(cpu_to_node(cpu));
    if (err)
        return err;

    cpu_maps_update_begin();

    if (cpu_hotplug_disabled) {
        err = -EBUSY;
        goto out;
    }
    if (!cpu_bootable(cpu)) {
        err = -EPERM;
        goto out;
    }

    err = _cpu_up(cpu, 0, target);
out:
    cpu_maps_update_done();
    return err;
}

static void __init cpuhp_bringup_mask(const struct cpumask *mask, unsigned int ncpus,
                      enum cpuhp_state target)
{
    unsigned int cpu;

    for_each_cpu(cpu, mask) {
        struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);

        if (cpu_up(cpu, target) && can_rollback_cpu(st)) {
            /*
             * If this failed then cpu_up() might have only
             * rolled back to CPUHP_BP_KICK_AP for the final
             * online. Clean it up. NOOP if already rolled back.
             */
            WARN_ON(cpuhp_invoke_callback_range(false, cpu, st, CPUHP_OFFLINE));
        }

        if (!--ncpus)
            break;
    }
}

static inline bool cpuhp_bringup_cpus_parallel(unsigned int ncpus) { return false; }

void __init bringup_nonboot_cpus(unsigned int max_cpus)
{
    if (!max_cpus)
        return;

    /* Try parallel bringup optimization if enabled */
    if (cpuhp_bringup_cpus_parallel(max_cpus))
        return;

    /* Full per CPU serialized bringup */
    cpuhp_bringup_mask(cpu_present_mask, max_cpus, CPUHP_ONLINE);
}

/*
 * The cpu hotplug threads manage the bringup and teardown of the cpus
 */
static int cpuhp_should_run(unsigned int cpu)
{
    struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);

    return st->should_run;
}

/*
 * Must be called _AFTER_ setting up the per_cpu areas
 */
void __init boot_cpu_hotplug_init(void)
{
#ifdef CONFIG_SMP
    cpumask_set_cpu(smp_processor_id(), &cpus_booted_once_mask);
    atomic_set(this_cpu_ptr(&cpuhp_state.ap_sync_state), SYNC_STATE_ONLINE);
#endif
    this_cpu_write(cpuhp_state.state, CPUHP_ONLINE);
    this_cpu_write(cpuhp_state.target, CPUHP_ONLINE);
}

/*
 * Execute teardown/startup callbacks on the plugged cpu. Also used to invoke
 * callbacks when a state gets [un]installed at runtime.
 *
 * Each invocation of this function by the smpboot thread does a single AP
 * state callback.
 *
 * It has 3 modes of operation:
 *  - single: runs st->cb_state
 *  - up:     runs ++st->state, while st->state < st->target
 *  - down:   runs st->state--, while st->state > st->target
 *
 * When complete or on error, should_run is cleared and the completion is fired.
 */
static void cpuhp_thread_fun(unsigned int cpu)
{
    printk("%s: cpu(%u)\n", __func__);
    PANIC("");
}

static struct smp_hotplug_thread cpuhp_threads = {
    .store          = &cpuhp_state.thread,
    .thread_should_run  = cpuhp_should_run,
    .thread_fn      = cpuhp_thread_fun,
    .thread_comm        = "cpuhp/%u",
    .selfparking        = true,
};

static __init void cpuhp_init_state(void)
{
    struct cpuhp_cpu_state *st;
    int cpu;

    for_each_possible_cpu(cpu) {
        st = per_cpu_ptr(&cpuhp_state, cpu);
        init_completion(&st->done_up);
        init_completion(&st->done_down);
    }
}

void __init cpuhp_threads_init(void)
{
    cpuhp_init_state();
    BUG_ON(smpboot_register_percpu_thread(&cpuhp_threads));
    kthread_unpark(this_cpu_read(cpuhp_state.thread));
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
