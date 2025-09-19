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
