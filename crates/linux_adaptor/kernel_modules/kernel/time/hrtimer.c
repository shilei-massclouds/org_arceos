#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/hrtimer.h>
#include <linux/notifier.h>
#include <linux/syscalls.h>
#include <linux/interrupt.h>
#include <linux/tick.h>
#include <linux/err.h>
#include <linux/debugobjects.h>
#include <linux/sched/signal.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/sched/deadline.h>
#include <linux/sched/nohz.h>
#include <linux/sched/debug.h>
#include <linux/sched/isolation.h>
#include <linux/timer.h>
#include <linux/freezer.h>
#include <linux/compat.h>

#include <linux/uaccess.h>

#include <trace/events/timer.h>

#include "tick-internal.h"

/*
 * Called from run_local_timers in hardirq context every jiffy
 */
void hrtimer_run_queues(void)
{
    pr_notice("%s: No impl.", __func__);
}

int hrtimers_cpu_starting(unsigned int cpu)
{
#if 0
    struct hrtimer_cpu_base *cpu_base = this_cpu_ptr(&hrtimer_bases);

    /* Clear out any left over state from a CPU down operation */
    cpu_base->active_bases = 0;
    cpu_base->hres_active = 0;
    cpu_base->hang_detected = 0;
    cpu_base->next_timer = NULL;
    cpu_base->softirq_next_timer = NULL;
    cpu_base->expires_next = KTIME_MAX;
    cpu_base->softirq_expires_next = KTIME_MAX;
    cpu_base->online = 1;
#endif
    pr_notice("%s: No impl.", __func__);
    return 0;
}
