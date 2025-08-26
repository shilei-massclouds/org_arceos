#include <linux/timekeeper_internal.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/nmi.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/clock.h>
#include <linux/syscore_ops.h>
#include <linux/clocksource.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/tick.h>
#include <linux/stop_machine.h>
#include <linux/pvclock_gtod.h>
#include <linux/compiler.h>
#include <linux/audit.h>
#include <linux/random.h>

#include "tick-internal.h"
#include "ntp_internal.h"
#include "timekeeping_internal.h"

#include "../adaptor.h"

ktime_t ktime_get(void)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

void ktime_get_coarse_real_ts64(struct timespec64 *ts)
{
    pr_err("%s: No impl.", __func__);
}

ktime_t ktime_get_with_offset(enum tk_offsets offs)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}

/*
 * Must hold jiffies_lock
 */
void do_timer(unsigned long ticks)
{
    jiffies_64 += ticks;
    //calc_global_load();
}
