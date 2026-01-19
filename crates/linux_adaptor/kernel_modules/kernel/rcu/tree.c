#include <linux/printk.h>

void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
    pr_notice("%s: No impl.", __func__);
}

void kvfree_call_rcu(struct rcu_head *head, void *ptr)
{
    pr_notice("%s: No impl.", __func__);
}

/**
 * rcu_is_watching - RCU read-side critical sections permitted on current CPU?
 *
 * Return @true if RCU is watching the running CPU and @false otherwise.
 * An @true return means that this CPU can safely enter RCU read-side
 * critical sections.
 *
 * Although calls to rcu_is_watching() from most parts of the kernel
 * will return @true, there are important exceptions.  For example, if the
 * current CPU is deep within its idle loop, in kernel entry/exit code,
 * or offline, rcu_is_watching() will return @false.
 *
 * Make notrace because it can be called by the internal functions of
 * ftrace, and making this notrace removes unnecessary recursion calls.
 */
notrace bool rcu_is_watching(void)
{
#if 0
    bool ret;

    preempt_disable_notrace();
    ret = rcu_is_watching_curr_cpu();
    preempt_enable_notrace();
    return ret;
#endif
    return true;
}

void synchronize_rcu(void)
{
    pr_notice("%s: No impl.", __func__);
}

/*
 * Mark the specified CPU as being online so that subsequent grace periods
 * (both expedited and normal) will wait on it.  Note that this means that
 * incoming CPUs are not allowed to use RCU read-side critical sections
 * until this function is called.  Failing to observe this restriction
 * will result in lockdep splats.
 *
 * Note that this function is special in that it is invoked directly
 * from the incoming CPU rather than from the cpuhp_step mechanism.
 * This is because this function must be invoked at a precise location.
 * This incoming CPU must not have enabled interrupts yet.
 *
 * This mirrors the effects of rcutree_report_cpu_dead().
 */
void rcutree_report_cpu_starting(unsigned int cpu)
{
    pr_notice("%s: No impl.", __func__);
}
