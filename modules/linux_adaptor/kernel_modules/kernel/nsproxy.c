#include <linux/slab.h>
#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/init_task.h>
#include <linux/mnt_namespace.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <net/net_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/time_namespace.h>
#include <linux/fs_struct.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/cgroup.h>
#include <linux/perf_event.h>

struct nsproxy init_nsproxy = {
    .count          = REFCOUNT_INIT(1),
    .uts_ns         = &init_uts_ns,
    /*
#if defined(CONFIG_POSIX_MQUEUE) || defined(CONFIG_SYSVIPC)
    .ipc_ns         = &init_ipc_ns,
#endif
    */
    .mnt_ns         = NULL,
    //.pid_ns_for_children    = &init_pid_ns,
#ifdef CONFIG_NET
    .net_ns         = &init_net,
#endif
    /*
#ifdef CONFIG_CGROUPS
    .cgroup_ns      = &init_cgroup_ns,
#endif
    */
    /*
#ifdef CONFIG_TIME_NS
    .time_ns        = &init_time_ns,
    .time_ns_for_children   = &init_time_ns,
#endif
    */
};
