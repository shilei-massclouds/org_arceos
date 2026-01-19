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

/**
 * rcu_sync_enter() - Force readers onto slowpath
 * @rsp: Pointer to rcu_sync structure to use for synchronization
 *
 * This function is used by updaters who need readers to make use of
 * a slowpath during the update.  After this function returns, all
 * subsequent calls to rcu_sync_is_idle() will return false, which
 * tells readers to stay off their fastpaths.  A later call to
 * rcu_sync_exit() re-enables reader fastpaths.
 *
 * When called in isolation, rcu_sync_enter() must wait for a grace
 * period, however, closely spaced calls to rcu_sync_enter() can
 * optimize away the grace-period wait via a state machine implemented
 * by rcu_sync_enter(), rcu_sync_exit(), and rcu_sync_func().
 */
void rcu_sync_enter(struct rcu_sync *rsp)
{
    pr_err("%s: No impl.", __func__);
}

/**
 * rcu_sync_exit() - Allow readers back onto fast path after grace period
 * @rsp: Pointer to rcu_sync structure to use for synchronization
 *
 * This function is used by updaters who have completed, and can therefore
 * now allow readers to make use of their fastpaths after a grace period
 * has elapsed.  After this grace period has completed, all subsequent
 * calls to rcu_sync_is_idle() will return true, which tells readers that
 * they can once again use their fastpaths.
 */
void rcu_sync_exit(struct rcu_sync *rsp)
{
    pr_err("%s: No impl.", __func__);
}
