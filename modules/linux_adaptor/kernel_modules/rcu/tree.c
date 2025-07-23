#include <linux/printk.h>

void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
    pr_err("%s: No impl.", __func__);
}
