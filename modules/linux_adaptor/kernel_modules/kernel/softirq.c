#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/local_lock.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/smp.h>
#include <linux/smpboot.h>
#include <linux/tick.h>
#include <linux/irq.h>
#include <linux/wait_bit.h>
#include <linux/workqueue.h>

#include <asm/softirq_stack.h>

#define CREATE_TRACE_POINTS
#include <trace/events/irq.h>

#include "../adaptor.h"

#ifndef __ARCH_IRQ_STAT
DEFINE_PER_CPU_ALIGNED(irq_cpustat_t, irq_stat);
#endif

DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static void wakeup_softirqd(void)
{
    pr_notice("%s: No impl.", __func__);
}

static inline void invoke_softirq(void)
{
    if (!force_irqthreads() || !__this_cpu_read(ksoftirqd)) {
#ifdef CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK
        /*
         * We can safely execute softirq on the current stack if
         * it is the irq stack, because it should be near empty
         * at this stage.
         */
        __do_softirq();
#else
        /*
         * Otherwise, irq_exit() is called on the task stack that can
         * be potentially deep already. So call softirq in its own stack
         * to prevent from any overrun.
         */
        do_softirq_own_stack();
#endif
    } else {
        wakeup_softirqd();
    }
}

void cl_invoke_softirq(void)
{
    invoke_softirq();
}

asmlinkage __visible void __softirq_entry __do_softirq(void)
{
    PANIC("");
    //handle_softirqs(false);
}
