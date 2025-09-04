#include <linux/ring_buffer.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/slab.h>
#include <linux/fs.h>

#include "trace.h"
#include "../adaptor.h"

/* Our option */
enum {

    TRACE_FUNC_NO_OPTS      = 0x0, /* No flags set. */
    TRACE_FUNC_OPT_STACK        = 0x1,
    TRACE_FUNC_OPT_NO_REPEATS   = 0x2,

    /* Update this to next highest bit. */
    TRACE_FUNC_OPT_HIGHEST_BIT  = 0x4
};

static struct tracer_opt func_opts[] = {
#ifdef CONFIG_STACKTRACE
    { TRACER_OPT(func_stack_trace, TRACE_FUNC_OPT_STACK) },
#endif
    { TRACER_OPT(func-no-repeats, TRACE_FUNC_OPT_NO_REPEATS) },
    { } /* Always set a last empty entry */
};

static int
func_set_flag(struct trace_array *tr, u32 old_flags, u32 bit, int set)
{
    PANIC("");
}

static struct tracer_flags func_flags = {
    .val = TRACE_FUNC_NO_OPTS, /* By default: all flags disabled */
    .opts = func_opts
};

static int function_trace_init(struct trace_array *tr)
{
    PANIC("");
}

static void function_trace_reset(struct trace_array *tr)
{
    PANIC("");
}

static void function_trace_start(struct trace_array *tr)
{
    PANIC("");
}

static struct tracer function_trace __tracer_data =
{
    .name       = "function",
    .init       = function_trace_init,
    .reset      = function_trace_reset,
    .start      = function_trace_start,
    .flags      = &func_flags,
    .set_flag   = func_set_flag,
    .allow_instances = true,
#ifdef CONFIG_FTRACE_SELFTEST
    .selftest   = trace_selftest_startup_function,
#endif
};

static inline int init_func_cmd_traceon(void)
{
    pr_notice("%s: No impl.", __func__);
    return 0;
}

__init int init_function_trace(void)
{
    printk("%s: ------------------\n", __func__);
    init_func_cmd_traceon();
    return register_tracer(&function_trace);
}
