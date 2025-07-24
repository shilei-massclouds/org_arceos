#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/wait.h>
#include <linux/lockdep.h>
#include <linux/percpu-rwsem.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/debug.h>
#include <linux/errno.h>
#include <trace/events/lock.h>

int __percpu_init_rwsem(struct percpu_rw_semaphore *sem,
            const char *name, struct lock_class_key *key)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}
