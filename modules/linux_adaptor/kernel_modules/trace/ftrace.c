#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/sched/task.h>
#include <linux/kallsyms.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/tracefs.h>
#include <linux/hardirq.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/bsearch.h>
#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/sort.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/rcupdate.h>
#include <linux/kprobes.h>

#include <trace/events/sched.h>

#include <asm/sections.h>
#include <asm/setup.h>

#include "ftrace_internal.h"
#include "trace_output.h"
#include "trace_stat.h"

#ifdef CONFIG_DYNAMIC_FTRACE
#define INIT_OPS_HASH(opsname)  \
    .func_hash      = &opsname.local_hash,          \
    .local_hash.regex_lock  = __MUTEX_INITIALIZER(opsname.local_hash.regex_lock), \
    .subop_list     = LIST_HEAD_INIT(opsname.subop_list),
#else
#define INIT_OPS_HASH(opsname)
#endif

/*
 * We make these constant because no one should touch them,
 * but they are used as the default "empty hash", to avoid allocating
 * it all the time. These are in a read only section such that if
 * anyone does try to modify it, it will cause an exception.
 */
static const struct hlist_head empty_buckets[1];
static const struct ftrace_hash empty_hash = {
    .buckets = (struct hlist_head *)empty_buckets,
};
#define EMPTY_HASH  ((struct ftrace_hash *)&empty_hash)

struct ftrace_ops global_ops = {
    .func               = ftrace_stub,
    .local_hash.notrace_hash    = EMPTY_HASH,
    .local_hash.filter_hash     = EMPTY_HASH,
    INIT_OPS_HASH(global_ops)
    .flags              = FTRACE_OPS_FL_INITIALIZED |
                      FTRACE_OPS_FL_PID,
};

void ftrace_init_trace_array(struct trace_array *tr)
{
    INIT_LIST_HEAD(&tr->func_probes);
    INIT_LIST_HEAD(&tr->mod_trace);
    INIT_LIST_HEAD(&tr->mod_notrace);
}

__init void ftrace_init_global_array_ops(struct trace_array *tr)
{
    tr->ops = &global_ops;
    tr->ops->private = tr;
    ftrace_init_trace_array(tr);
    init_array_fgraph_ops(tr, tr->ops);
}
