#include <linux/ring_buffer.h>
#include <linux/utsname.h>
#include <linux/stacktrace.h>
#include <linux/writeback.h>
#include <linux/kallsyms.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/irqflags.h>
#include <linux/debugfs.h>
#include <linux/tracefs.h>
#include <linux/pagemap.h>
#include <linux/hardirq.h>
#include <linux/linkage.h>
#include <linux/uaccess.h>
#include <linux/cleanup.h>
#include <linux/vmalloc.h>
#include <linux/ftrace.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/splice.h>
#include <linux/kdebug.h>
#include <linux/string.h>
#include <linux/mount.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/panic_notifier.h>
#include <linux/poll.h>
#include <linux/nmi.h>
#include <linux/fs.h>
#include <linux/trace.h>
#include <linux/sched/clock.h>
#include <linux/sched/rt.h>
#include <linux/fsnotify.h>
#include <linux/irq_work.h>
#include <linux/workqueue.h>

#include <asm/setup.h> /* COMMAND_LINE_SIZE */

#include "trace.h"
#include "trace_output.h"
#include "../adaptor.h"

/* trace_flags holds trace_options default values */
#define TRACE_DEFAULT_FLAGS                     \
    (FUNCTION_DEFAULT_FLAGS |                   \
     TRACE_ITER_PRINT_PARENT | TRACE_ITER_PRINTK |          \
     TRACE_ITER_ANNOTATE | TRACE_ITER_CONTEXT_INFO |        \
     TRACE_ITER_RECORD_CMD | TRACE_ITER_OVERWRITE |         \
     TRACE_ITER_IRQ_INFO | TRACE_ITER_MARKERS |         \
     TRACE_ITER_HASH_PTR | TRACE_ITER_TRACE_PRINTK)

static int boot_instance_index;

LIST_HEAD(ftrace_trace_arrays);

/*
 * The global_trace is the descriptor that holds the top-level tracing
 * buffers for the live tracing.
 */
static struct trace_array global_trace = {
    .trace_flags = TRACE_DEFAULT_FLAGS,
};

__init static void enable_instances(void)
{
    PANIC("");
}

__init static int tracer_alloc_buffers(void)
{
    global_trace.flags = TRACE_ARRAY_FL_GLOBAL;
    list_add(&global_trace.list, &ftrace_trace_arrays);
}

void __init early_trace_init(void)
{
#if 0
    if (tracepoint_printk) {
        tracepoint_print_iter =
            kzalloc(sizeof(*tracepoint_print_iter), GFP_KERNEL);
        if (MEM_FAIL(!tracepoint_print_iter,
                 "Failed to allocate trace iterator\n"))
            tracepoint_printk = 0;
        else
            static_key_enable(&tracepoint_printk_key.key);
    }
#endif
    tracer_alloc_buffers();

#if 0
    init_events();
#endif
}

void __init trace_init(void)
{
    trace_event_init();

    if (boot_instance_index)
        enable_instances();
}
