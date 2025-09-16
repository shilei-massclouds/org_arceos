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
#include "../sched/smp.h"
#include "../adaptor.h"

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

static void smp_call_function_many_cond(const struct cpumask *mask,
                    smp_call_func_t func, void *info,
                    unsigned int scf_flags,
                    smp_cond_func_t cond_func)
{
    PANIC("");
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
