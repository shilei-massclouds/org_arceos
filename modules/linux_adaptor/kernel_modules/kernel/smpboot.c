// SPDX-License-Identifier: GPL-2.0-only
/*
 * Common SMP CPU bringup/teardown functions
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/kthread.h>
#include <linux/smpboot.h>

#include "smpboot.h"
#include "adaptor.h"

/**
 * idle_init - Initialize the idle thread for a cpu
 * @cpu:    The cpu for which the idle thread should be initialized
 *
 * Creates the thread if it does not exist.
 */
static __always_inline void idle_init(unsigned int cpu)
{
#if 0
    struct task_struct *tsk = per_cpu(idle_threads, cpu);

    if (!tsk) {
        tsk = fork_idle(cpu);
        if (IS_ERR(tsk))
            pr_err("SMP: fork_idle() failed for CPU %u\n", cpu);
        else
            per_cpu(idle_threads, cpu) = tsk;
    }
#endif
    pr_err("%s: No impl.", __func__);
    //PANIC("");
}

/**
 * idle_threads_init - Initialize idle threads for all cpus
 */
void __init idle_threads_init(void)
{
    unsigned int cpu, boot_cpu;

    boot_cpu = smp_processor_id();

    for_each_possible_cpu(cpu) {
        printk("%s: cpu[%u]\n", __func__, cpu);
        if (cpu != boot_cpu)
            idle_init(cpu);
    }
    pr_err("%s: No impl.", __func__);
    //PANIC("");
}
