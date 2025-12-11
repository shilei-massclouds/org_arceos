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
        PANIC("");
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
        PANIC("");
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
