#include <linux/rcu_sync.h>
#include <linux/sched.h>

/**
 * rcu_sync_init() - Initialize an rcu_sync structure
 * @rsp: Pointer to rcu_sync structure to be initialized
 */
void rcu_sync_init(struct rcu_sync *rsp)
{
    memset(rsp, 0, sizeof(*rsp));
    init_waitqueue_head(&rsp->gp_wait);
}
