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

struct kthread {
    unsigned long flags;
    unsigned int cpu;
    int result;
    int (*threadfn)(void *);
    void *data;
    struct completion parked;
    struct completion exited;
#ifdef CONFIG_BLK_CGROUP
    struct cgroup_subsys_state *blkcg_css;
#endif
    /* To store the full name if task comm is truncated. */
    char *full_name;
};

enum KTHREAD_BITS {
    KTHREAD_IS_PER_CPU = 0,
    KTHREAD_SHOULD_STOP,
    KTHREAD_SHOULD_PARK,
};

static inline struct kthread *to_kthread(struct task_struct *k)
{
    WARN_ON(!(k->flags & PF_KTHREAD));
    return k->worker_private;
}

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

static __printf(4, 0)
struct task_struct *__kthread_create_on_node(int (*threadfn)(void *data),
                            void *data, int node,
                            const char namefmt[],
                            va_list args)
{
    char name[512];
    struct task_struct *task = kmalloc(sizeof(struct task_struct), 0);
    unsigned long tid = cl_kthread_run((unsigned long)task,
                                       (unsigned long)threadfn,
                                       (unsigned long)data);

    vscnprintf(name, sizeof(name), namefmt, args);
    printk("%s: curr(%lx:%u) tid[%lu] name[%s]\n",
           __func__, current, current->__state, tid, name);
    printk("%s: ioc(%lx)\n", __func__, task->io_context);
    task->pid = tid;
    task->flags |= PF_KTHREAD;
    WRITE_ONCE(task->__state, TASK_RUNNING);
    set_kthread_struct(task);
    return task;
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
    struct task_struct *task;
    va_list args;

    va_start(args, namefmt);
    task = __kthread_create_on_node(threadfn, data, node, namefmt, args);
    va_end(args);

    return task;
}

static __printf(3, 0) struct kthread_worker *
__kthread_create_worker(int cpu, unsigned int flags,
            const char namefmt[], va_list args)
{
    struct kthread_worker *worker;
    struct task_struct *task;
    int node = NUMA_NO_NODE;

    worker = kzalloc(sizeof(*worker), GFP_KERNEL);
    if (!worker)
        return ERR_PTR(-ENOMEM);

    kthread_init_worker(worker);

    if (cpu >= 0)
        node = cpu_to_node(cpu);

    task = __kthread_create_on_node(kthread_worker_fn, worker,
                        node, namefmt, args);
    if (IS_ERR(task))
        goto fail_task;

    if (cpu >= 0)
        kthread_bind(task, cpu);

    worker->flags = flags;
    worker->task = task;
    wake_up_process(task);
    return worker;

fail_task:
    kfree(worker);
    return ERR_CAST(task);
}

/**
 * kthread_create_worker - create a kthread worker
 * @flags: flags modifying the default behavior of the worker
 * @namefmt: printf-style name for the kthread worker (task).
 *
 * Returns a pointer to the allocated worker on success, ERR_PTR(-ENOMEM)
 * when the needed structures could not get allocated, and ERR_PTR(-EINTR)
 * when the caller was killed by a fatal signal.
 */
struct kthread_worker *
kthread_create_worker(unsigned int flags, const char namefmt[], ...)
{
    struct kthread_worker *worker;
    va_list args;

    va_start(args, namefmt);
    worker = __kthread_create_worker(-1, flags, namefmt, args);
    va_end(args);

    return worker;
}

void __kthread_init_worker(struct kthread_worker *worker,
                const char *name,
                struct lock_class_key *key)
{
    memset(worker, 0, sizeof(struct kthread_worker));
    raw_spin_lock_init(&worker->lock);
    lockdep_set_class_and_name(&worker->lock, key, name);
    INIT_LIST_HEAD(&worker->work_list);
    INIT_LIST_HEAD(&worker->delayed_work_list);
}

/**
 * kthread_worker_fn - kthread function to process kthread_worker
 * @worker_ptr: pointer to initialized kthread_worker
 *
 * This function implements the main cycle of kthread worker. It processes
 * work_list until it is stopped with kthread_stop(). It sleeps when the queue
 * is empty.
 *
 * The works are not allowed to keep any locks, disable preemption or interrupts
 * when they finish. There is defined a safe point for freezing when one work
 * finishes and before a new one is started.
 *
 * Also the works must not be handled by more than one worker at the same time,
 * see also kthread_queue_work().
 */
int kthread_worker_fn(void *worker_ptr)
{
    struct kthread_worker *worker = worker_ptr;
    struct kthread_work *work;

    /*
     * FIXME: Update the check and remove the assignment when all kthread
     * worker users are created using kthread_create_worker*() functions.
     */
    WARN_ON(worker->task && worker->task != current);
    worker->task = current;

    if (worker->flags & KTW_FREEZABLE)
        set_freezable();
repeat:
    set_current_state(TASK_INTERRUPTIBLE);  /* mb paired w/ kthread_stop */

    printk("%s: step1\n", __func__);
    if (kthread_should_stop()) {
    printk("%s: step2\n", __func__);
        __set_current_state(TASK_RUNNING);
        raw_spin_lock_irq(&worker->lock);
        worker->task = NULL;
        raw_spin_unlock_irq(&worker->lock);
        return 0;
    }

    work = NULL;
    raw_spin_lock_irq(&worker->lock);
    if (!list_empty(&worker->work_list)) {
        work = list_first_entry(&worker->work_list,
                    struct kthread_work, node);
        list_del_init(&work->node);
    }
    worker->current_work = work;
    raw_spin_unlock_irq(&worker->lock);

    if (work) {
        kthread_work_func_t func = work->func;
        __set_current_state(TASK_RUNNING);
        trace_sched_kthread_work_execute_start(work);
        work->func(work);
        /*
         * Avoid dereferencing work after this point.  The trace
         * event only cares about the address.
         */
        trace_sched_kthread_work_execute_end(work, func);
    } else if (!freezing(current)) {
        schedule();
    } else {
        /*
         * Handle the case where the current remains
         * TASK_INTERRUPTIBLE. try_to_freeze() expects
         * the current to be TASK_RUNNING.
         */
        __set_current_state(TASK_RUNNING);
    }

    try_to_freeze();
    cond_resched();
    goto repeat;
}

/**
 * kthread_should_stop - should this kthread return now?
 *
 * When someone calls kthread_stop() on your kthread, it will be woken
 * and this will return true.  You should then return, and your return
 * value will be passed through to kthread_stop().
 */
bool kthread_should_stop(void)
{
    return test_bit(KTHREAD_SHOULD_STOP, &to_kthread(current)->flags);
}

static void __kthread_bind_mask(struct task_struct *p, const struct cpumask *mask, unsigned int state)
{
    unsigned long flags;

#if 0
    if (!wait_task_inactive(p, state)) {
        WARN_ON(1);
        return;
    }
#endif

    /* It's safe because the task is inactive. */
    raw_spin_lock_irqsave(&p->pi_lock, flags);
#if 0
    do_set_cpus_allowed(p, mask);
#endif
    pr_err("%s: No impl.", __func__);
    p->flags |= PF_NO_SETAFFINITY;
    raw_spin_unlock_irqrestore(&p->pi_lock, flags);
}

void kthread_bind_mask(struct task_struct *p, const struct cpumask *mask)
{
    __kthread_bind_mask(p, mask, TASK_UNINTERRUPTIBLE);
}

void kthread_set_per_cpu(struct task_struct *k, int cpu)
{
    struct kthread *kthread = to_kthread(k);
    if (!kthread)
        return;

    WARN_ON_ONCE(!(k->flags & PF_NO_SETAFFINITY));

    if (cpu < 0) {
        clear_bit(KTHREAD_IS_PER_CPU, &kthread->flags);
        return;
    }

    kthread->cpu = cpu;
    set_bit(KTHREAD_IS_PER_CPU, &kthread->flags);
}

bool set_kthread_struct(struct task_struct *p)
{
    struct kthread *kthread;

    if (WARN_ON_ONCE(to_kthread(p)))
        return false;

    kthread = kzalloc(sizeof(*kthread), GFP_KERNEL);
    if (!kthread)
        return false;

    init_completion(&kthread->exited);
    init_completion(&kthread->parked);
    p->vfork_done = &kthread->exited;

    p->worker_private = kthread;
    return true;
}

/**
 * kthread_data - return data value specified on kthread creation
 * @task: kthread task in question
 *
 * Return the data value specified when kthread @task was created.
 * The caller is responsible for ensuring the validity of @task when
 * calling this function.
 */
void *kthread_data(struct task_struct *task)
{
    return to_kthread(task)->data;
}
