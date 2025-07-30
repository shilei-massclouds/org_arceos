#include <uapi/linux/sched/types.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/cgroup.h>
#include <linux/cpuset.h>
#include <linux/unistd.h>
#include <linux/file.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/freezer.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/numa.h>
#include <linux/sched/isolation.h>
#include <trace/events/sched.h>

#include "../adaptor.h"

/**
 * kthread_stop_put - stop a thread and put its task struct
 * @k: thread created by kthread_create().
 *
 * Stops a thread created by kthread_create() and put its task_struct.
 * Only use when holding an extra task struct reference obtained by
 * calling get_task_struct().
 */
int kthread_stop_put(struct task_struct *k)
{
    PANIC("");
#if 0
    int ret;

    ret = kthread_stop(k);
    put_task_struct(k);
    return ret;
#endif
}

/**
 * kthread_create_on_node - create a kthread.
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @node: task and thread structures for the thread are allocated on this node
 * @namefmt: printf-style name for the thread.
 *
 * Description: This helper function creates and names a kernel
 * thread.  The thread will be stopped: use wake_up_process() to start
 * it.  See also kthread_run().  The new thread has SCHED_NORMAL policy and
 * is affine to all CPUs.
 *
 * If thread is going to be bound on a particular cpu, give its node
 * in @node, to get NUMA affinity for kthread stack, or else give NUMA_NO_NODE.
 * When woken, the thread will run @threadfn() with @data as its
 * argument. @threadfn() can either return directly if it is a
 * standalone thread for which no one will call kthread_stop(), or
 * return when 'kthread_should_stop()' is true (which means
 * kthread_stop() has been called).  The return value should be zero
 * or a negative error number; it will be passed to kthread_stop().
 *
 * Returns a task_struct or ERR_PTR(-ENOMEM) or ERR_PTR(-EINTR).
 */
struct task_struct *kthread_create_on_node(int (*threadfn)(void *data),
                       void *data, int node,
                       const char namefmt[],
                       ...)
{
    struct task_struct *task = kmalloc(sizeof(struct task_struct), 0);
    unsigned long tid = cl_kthread_run(task, threadfn, data);
    printk("%s: kthread[%lu]\n", __func__, tid);
    task->pid = tid;
    return task;

#if 0
    struct task_struct *task;
    va_list args;

    va_start(args, namefmt);
    task = __kthread_create_on_node(threadfn, data, node, namefmt, args);
    va_end(args);

    return task;
#endif
}
