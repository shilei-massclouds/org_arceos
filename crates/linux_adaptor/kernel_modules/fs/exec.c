#include <linux/kernel_read_file.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/signal.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/perf_event.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/audit.h>
#include <linux/kmod.h>
#include <linux/fsnotify.h>
#include <linux/fs_struct.h>
#include <linux/oom.h>
#include <linux/compat.h>
#include <linux/vmalloc.h>
#include <linux/io_uring.h>
#include <linux/syscall_user_dispatch.h>
#include <linux/coredump.h>
#include <linux/time_namespace.h>
#include <linux/user_events.h>
#include <linux/rseq.h>
#include <linux/ksm.h>

#include <linux/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/tlb.h>

#include <trace/events/task.h>
#include "internal.h"

#include <trace/events/sched.h>

bool path_noexec(const struct path *path)
{
    return (path->mnt->mnt_flags & MNT_NOEXEC) ||
           (path->mnt->mnt_sb->s_iflags & SB_I_NOEXEC);
}
