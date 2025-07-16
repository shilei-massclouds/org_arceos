#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/resource.h>
#include <linux/fs.h>
#include <linux/mqueue.h>

static struct signal_struct signal_dummy = {
    .rlim = INIT_RLIMITS
};

static struct task_struct task_dummy = {
    /*
#ifdef CONFIG_THREAD_INFO_IN_TASK
    .thread_info    = INIT_THREAD_INFO(init_task),
    .stack_refcount = REFCOUNT_INIT(1),
#endif
    */
    .signal = &signal_dummy
};

unsigned long init_current(unsigned long thread_id)
{
    struct task_struct *tsk = &task_dummy;
    task_dummy.pid = thread_id;
    __asm__ __volatile__ (
        "mv tp, %0"
        : : "rK" (tsk)
        : "memory"
    );
    pr_debug("%s: init_task(%lu) ptr (0x%lx)\n", __func__, thread_id, tsk);
    return (unsigned long)tsk;
}

void __init sched_init(void)
{
    wait_bit_init();
}
