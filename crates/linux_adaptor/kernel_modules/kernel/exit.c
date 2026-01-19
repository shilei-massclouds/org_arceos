#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/mm.h>
#include <linux/sched/stat.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/tty.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/cpu.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/freezer.h>
#include <linux/binfmts.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/profile.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/cgroup.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/posix-timers.h>
#include <linux/cn_proc.h>
#include <linux/mutex.h>
#include <linux/futex.h>
#include <linux/pipe_fs_i.h>
#include <linux/audit.h> /* for audit_free() */
#include <linux/resource.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/blkdev.h>
#include <linux/task_work.h>
#include <linux/fs_struct.h>
#include <linux/init_task.h>
#include <linux/perf_event.h>
#include <trace/events/sched.h>
#include <linux/hw_breakpoint.h>
#include <linux/oom.h>
#include <linux/writeback.h>
#include <linux/shm.h>
#include <linux/kcov.h>
#include <linux/kmsan.h>
#include <linux/random.h>
#include <linux/rcuwait.h>
#include <linux/compat.h>
#include <linux/io_uring.h>
#include <linux/kprobes.h>
#include <linux/rethook.h>
#include <linux/sysfs.h>
#include <linux/user_events.h>
#include <linux/uaccess.h>

#include <uapi/linux/wait.h>

#include <asm/unistd.h>
#include <asm/mmu_context.h>

#include "exit.h"

int rcuwait_wake_up(struct rcuwait *w)
{
    int ret = 0;
    struct task_struct *task;

    pr_debug("%s: Note: w(%lx)\n", __func__, w);

    rcu_read_lock();

    /*
     * Order condition vs @task, such that everything prior to the load
     * of @task is visible. This is the condition as to why the user called
     * rcuwait_wake() in the first place. Pairs with set_current_state()
     * barrier (A) in rcuwait_wait_event().
     *
     *    WAIT                WAKE
     *    [S] tsk = current   [S] cond = true
     *        MB (A)          MB (B)
     *    [L] cond        [L] tsk
     */
    smp_mb(); /* (B) */

    task = rcu_dereference(w->task);
    if (task)
        ret = wake_up_process(task);
    rcu_read_unlock();

    return ret;
}
