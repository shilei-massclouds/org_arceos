#define pr_fmt(fmt) "rcu: " fmt

#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate_wait.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/srcu.h>

#include "rcu.h"
#include "rcu_segcblist.h"

/**
 * init_srcu_struct - initialize a sleep-RCU structure
 * @ssp: structure to initialize.
 *
 * Must invoke this on a given srcu_struct before passing that srcu_struct
 * to any other function.  Each srcu_struct represents a separate domain
 * of SRCU protection.
 */
int init_srcu_struct(struct srcu_struct *ssp)
{
    pr_err("%s: No impl.", __func__);
    return 0;
    //return init_srcu_struct_fields(ssp, false);
}

void synchronize_srcu(struct srcu_struct *ssp)
{
    pr_err("%s: No impl.", __func__);
#if 0
    if (srcu_might_be_idle(ssp) || rcu_gp_is_expedited())
        synchronize_srcu_expedited(ssp);
    else
        __synchronize_srcu(ssp, true);
#endif
}
