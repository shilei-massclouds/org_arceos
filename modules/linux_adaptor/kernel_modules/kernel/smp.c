// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic helpers for smp ipi calls
 *
 * (C) Jens Axboe <jens.axboe@oracle.com> 2008
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/irq_work.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/gfp.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/sched/idle.h>
#include <linux/hypervisor.h>
#include <linux/sched/clock.h>
#include <linux/nmi.h>
#include <linux/sched/debug.h>
#include <linux/jump_label.h>
#include <linux/string_choices.h>

#include <trace/events/ipi.h>
#define CREATE_TRACE_POINTS
#include <trace/events/csd.h>
#undef CREATE_TRACE_POINTS

#include "smpboot.h"
#include "sched/smp.h"
#include "adaptor.h"

#define CSD_TYPE(_csd)  ((_csd)->node.u_flags & CSD_FLAG_TYPE_MASK)

struct call_function_data {
    call_single_data_t  __percpu *csd;
    cpumask_var_t       cpumask;
    cpumask_var_t       cpumask_ipi;
};

static DEFINE_PER_CPU_ALIGNED(struct call_function_data, cfd_data);

static DEFINE_PER_CPU_SHARED_ALIGNED(struct llist_head, call_single_queue);

/*
 * Flags to be used as scf_flags argument of smp_call_function_many_cond().
 *
 * %SCF_WAIT:       Wait until function execution is completed
 * %SCF_RUN_LOCAL:  Run also locally if local cpu is set in cpumask
 */
#define SCF_WAIT    (1U << 0)
#define SCF_RUN_LOCAL   (1U << 1)

#define CSD_TYPE(_csd)  ((_csd)->node.u_flags & CSD_FLAG_TYPE_MASK)

#if (NR_CPUS > 1) && !defined(CONFIG_FORCE_NR_CPUS)
/* Setup number of possible processor ids */
unsigned int nr_cpu_ids __read_mostly = NR_CPUS;
EXPORT_SYMBOL(nr_cpu_ids);
#endif

/* Setup configured maximum number of CPUs to activate */
unsigned int setup_max_cpus = NR_CPUS;

static void csd_lock_record(call_single_data_t *csd)
{
}

static __always_inline void csd_lock_wait(call_single_data_t *csd)
{
    smp_cond_load_acquire(&csd->node.u_flags, !(VAL & CSD_FLAG_LOCK));
}

static __always_inline void csd_lock(call_single_data_t *csd)
{
    csd_lock_wait(csd);
    csd->node.u_flags |= CSD_FLAG_LOCK;

    /*
     * prevent CPU from reordering the above assignment
     * to ->flags with any subsequent assignments to other
     * fields of the specified call_single_data_t structure:
     */
    smp_wmb();
}

static __always_inline void csd_unlock(call_single_data_t *csd)
{
    WARN_ON(!(csd->node.u_flags & CSD_FLAG_LOCK));

    /*
     * ensure we're all done before releasing data:
     */
    smp_store_release(&csd->node.u_flags, 0);
}

static __always_inline void
csd_do_func(smp_call_func_t func, void *info, call_single_data_t *csd)
{
    trace_csd_function_entry(func, csd);
    func(info);
    trace_csd_function_exit(func, csd);
}

static void smp_call_function_many_cond(const struct cpumask *mask,
                    smp_call_func_t func, void *info,
                    unsigned int scf_flags,
                    smp_cond_func_t cond_func)
{
    int cpu, last_cpu, this_cpu = smp_processor_id();
    struct call_function_data *cfd;
    bool wait = scf_flags & SCF_WAIT;
    int nr_cpus = 0;
    bool run_remote = false;
    bool run_local = false;

    lockdep_assert_preemption_disabled();

    /*
     * Can deadlock when called with interrupts disabled.
     * We allow cpu's that are not yet online though, as no one else can
     * send smp call function interrupt to this cpu and as such deadlocks
     * can't happen.
     */
    if (cpu_online(this_cpu) && !oops_in_progress &&
        !early_boot_irqs_disabled)
        lockdep_assert_irqs_enabled();

    /*
     * When @wait we can deadlock when we interrupt between llist_add() and
     * arch_send_call_function_ipi*(); when !@wait we can deadlock due to
     * csd_lock() on because the interrupt context uses the same csd
     * storage.
     */
    WARN_ON_ONCE(!in_task());

    /* Check if we need local execution. */
    if ((scf_flags & SCF_RUN_LOCAL) && cpumask_test_cpu(this_cpu, mask))
        run_local = true;

    /* Check if we need remote execution, i.e., any CPU excluding this one. */
    cpu = cpumask_first_and(mask, cpu_online_mask);
    if (cpu == this_cpu)
        cpu = cpumask_next_and(cpu, mask, cpu_online_mask);
    if (cpu < nr_cpu_ids)
        run_remote = true;

    if (run_remote) {
#if 0
        cfd = this_cpu_ptr(&cfd_data);
        cpumask_and(cfd->cpumask, mask, cpu_online_mask);
        __cpumask_clear_cpu(this_cpu, cfd->cpumask);

        cpumask_clear(cfd->cpumask_ipi);
        for_each_cpu(cpu, cfd->cpumask) {
            call_single_data_t *csd = per_cpu_ptr(cfd->csd, cpu);

            if (cond_func && !cond_func(cpu, info)) {
                __cpumask_clear_cpu(cpu, cfd->cpumask);
                continue;
            }

            csd_lock(csd);
            if (wait)
                csd->node.u_flags |= CSD_TYPE_SYNC;
            csd->func = func;
            csd->info = info;
#ifdef CONFIG_CSD_LOCK_WAIT_DEBUG
            csd->node.src = smp_processor_id();
            csd->node.dst = cpu;
#endif
            trace_csd_queue_cpu(cpu, _RET_IP_, func, csd);

            if (llist_add(&csd->node.llist, &per_cpu(call_single_queue, cpu))) {
                __cpumask_set_cpu(cpu, cfd->cpumask_ipi);
                nr_cpus++;
                last_cpu = cpu;
            }
        }

        /*
         * Choose the most efficient way to send an IPI. Note that the
         * number of CPUs might be zero due to concurrent changes to the
         * provided mask.
         */
        if (nr_cpus == 1)
            send_call_function_single_ipi(last_cpu);
        else if (likely(nr_cpus > 1))
            send_call_function_ipi_mask(cfd->cpumask_ipi);
#endif
        //PANIC("");
        pr_err("%s: No impl step1.", __func__);
    }

    if (run_local && (!cond_func || cond_func(this_cpu, info))) {
        unsigned long flags;

        local_irq_save(flags);
        csd_do_func(func, info, NULL);
        local_irq_restore(flags);
    }

    if (run_remote && wait) {
#if 0
        for_each_cpu(cpu, cfd->cpumask) {
            call_single_data_t *csd;

            csd = per_cpu_ptr(cfd->csd, cpu);
            csd_lock_wait(csd);
        }
#endif
        //PANIC("");
        pr_err("%s: No impl step2.", __func__);
    }
}

/*
 * on_each_cpu_cond(): Call a function on each processor for which
 * the supplied function cond_func returns true, optionally waiting
 * for all the required CPUs to finish. This may include the local
 * processor.
 * @cond_func:  A callback function that is passed a cpu id and
 *      the info parameter. The function is called
 *      with preemption disabled. The function should
 *      return a blooean value indicating whether to IPI
 *      the specified CPU.
 * @func:   The function to run on all applicable CPUs.
 *      This must be fast and non-blocking.
 * @info:   An arbitrary pointer to pass to both functions.
 * @wait:   If true, wait (atomically) until function has
 *      completed on other CPUs.
 *
 * Preemption is disabled to protect against CPUs going offline but not online.
 * CPUs going online during the call will not be seen or sent an IPI.
 *
 * You must not call this function with disabled interrupts or
 * from a hardware interrupt handler or from a bottom half handler.
 */
void on_each_cpu_cond_mask(smp_cond_func_t cond_func, smp_call_func_t func,
               void *info, bool wait, const struct cpumask *mask)
{
    unsigned int scf_flags = SCF_RUN_LOCAL;

    if (wait)
        scf_flags |= SCF_WAIT;

    preempt_disable();
    smp_call_function_many_cond(mask, func, info, scf_flags, cond_func);
    preempt_enable();
}

/* An arch may set nr_cpu_ids earlier if needed, so this would be redundant */
void __init setup_nr_cpu_ids(void)
{
    set_nr_cpu_ids(find_last_bit(cpumask_bits(cpu_possible_mask), NR_CPUS) + 1);
}

/* Called by boot processor to activate the rest. */
void __init smp_init(void)
{
    int num_nodes, num_cpus;

    idle_threads_init();
    //cpuhp_threads_init();

    pr_info("Bringing up secondary CPUs ...\n");

    bringup_nonboot_cpus(setup_max_cpus);

    num_nodes = num_online_nodes();
    num_cpus  = num_online_cpus();
    pr_info("Brought up %d node%s, %d CPU%s\n",
        num_nodes, str_plural(num_nodes), num_cpus, str_plural(num_cpus));

    /* Any cleanup work */
    smp_cpus_done(setup_max_cpus);
}

/*
 * Insert a previously allocated call_single_data_t element
 * for execution on the given CPU. data must already have
 * ->func, ->info, and ->flags set.
 */
static int generic_exec_single(int cpu, call_single_data_t *csd)
{
    if (cpu == smp_processor_id()) {
        smp_call_func_t func = csd->func;
        void *info = csd->info;
        unsigned long flags;

        /*
         * We can unlock early even for the synchronous on-stack case,
         * since we're doing this from the same CPU..
         */
        csd_lock_record(csd);
        csd_unlock(csd);
        local_irq_save(flags);
        csd_do_func(func, info, NULL);
        csd_lock_record(NULL);
        local_irq_restore(flags);
        return 0;
    }

    if ((unsigned)cpu >= nr_cpu_ids || !cpu_online(cpu)) {
        csd_unlock(csd);
        return -ENXIO;
    }

    __smp_call_single_queue(cpu, &csd->node.llist);

    return 0;
}

int smp_call_function_single_async(int cpu, call_single_data_t *csd)
{
    int err = 0;

    preempt_disable();

    if (csd->node.u_flags & CSD_FLAG_LOCK) {
        err = -EBUSY;
        goto out;
    }

    csd->node.u_flags = CSD_FLAG_LOCK;
    smp_wmb();

    err = generic_exec_single(cpu, csd);

out:
    preempt_enable();

    return err;
}

int smpcfd_prepare_cpu(unsigned int cpu)
{
    struct call_function_data *cfd = &per_cpu(cfd_data, cpu);

    if (!zalloc_cpumask_var_node(&cfd->cpumask, GFP_KERNEL,
                     cpu_to_node(cpu)))
        return -ENOMEM;
    if (!zalloc_cpumask_var_node(&cfd->cpumask_ipi, GFP_KERNEL,
                     cpu_to_node(cpu))) {
        free_cpumask_var(cfd->cpumask);
        return -ENOMEM;
    }
    cfd->csd = alloc_percpu(call_single_data_t);
    if (!cfd->csd) {
        free_cpumask_var(cfd->cpumask);
        free_cpumask_var(cfd->cpumask_ipi);
        return -ENOMEM;
    }

    return 0;
}

static __always_inline void
send_call_function_single_ipi(int cpu)
{
    if (call_function_single_prep_ipi(cpu)) {
        trace_ipi_send_cpu(cpu, _RET_IP_,
                   generic_smp_call_function_single_interrupt);
        arch_send_call_function_single_ipi(cpu);
    }
}

/**
 * generic_smp_call_function_single_interrupt - Execute SMP IPI callbacks
 *
 * Invoked by arch to handle an IPI for call function single.
 * Must be called with interrupts disabled.
 */
void generic_smp_call_function_single_interrupt(void)
{
    PANIC("");
    //__flush_smp_call_function_queue(true);
}

void __smp_call_single_queue(int cpu, struct llist_node *node)
{
    /*
     * We have to check the type of the CSD before queueing it, because
     * once queued it can have its flags cleared by
     *   flush_smp_call_function_queue()
     * even if we haven't sent the smp_call IPI yet (e.g. the stopper
     * executes migration_cpu_stop() on the remote CPU).
     */
    if (trace_csd_queue_cpu_enabled()) {
        call_single_data_t *csd;
        smp_call_func_t func;

        csd = container_of(node, call_single_data_t, node.llist);
        func = CSD_TYPE(csd) == CSD_TYPE_TTWU ?
            sched_ttwu_pending : csd->func;

        trace_csd_queue_cpu(cpu, _RET_IP_, func, csd);
    }

    /*
     * The list addition should be visible to the target CPU when it pops
     * the head of the list to pull the entry off it in the IPI handler
     * because of normal cache coherency rules implied by the underlying
     * llist ops.
     *
     * If IPIs can go out of order to the cache coherency protocol
     * in an architecture, sufficient synchronisation should be added
     * to arch code to make it appear to obey cache coherency WRT
     * locking and barrier primitives. Generic code isn't really
     * equipped to do the right thing...
     */
    if (llist_add(node, &per_cpu(call_single_queue, cpu)))
        send_call_function_single_ipi(cpu);
}

void __init call_function_init(void)
{
    int i;

    for_each_possible_cpu(i)
        init_llist_head(&per_cpu(call_single_queue, i));

    smpcfd_prepare_cpu(smp_processor_id());
}
