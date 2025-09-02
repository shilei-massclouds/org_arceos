// SPDX-License-Identifier: GPL-2.0
#include <trace/syscall.h>
#include <trace/events/syscalls.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>   /* for MODULE_NAME_LEN via KSYM_SYMBOL_LEN */
#include <linux/ftrace.h>
#include <linux/perf_event.h>
#include <linux/xarray.h>
#include <asm/syscall.h>

#include "trace_output.h"
#include "trace.h"
#include "../adaptor.h"

#define SYSCALL_FIELD(_type, _name) {                   \
    .type = #_type, .name = #_name,                 \
    .size = sizeof(_type), .align = __alignof__(_type),     \
    .is_signed = is_signed_type(_type), .filter_type = FILTER_OTHER }

static DEFINE_XARRAY(syscalls_metadata_sparse);
static struct syscall_metadata **syscalls_metadata;

static int __init init_syscall_trace(struct trace_event_call *call)
{
    int id;
    int num;

    num = ((struct syscall_metadata *)call->data)->syscall_nr;
    if (num < 0 || num >= NR_syscalls) {
        pr_debug("syscall %s metadata not mapped, disabling ftrace event\n",
                ((struct syscall_metadata *)call->data)->name);
        return -ENOSYS;
    }

#if 0
    if (set_syscall_print_fmt(call) < 0)
        return -ENOMEM;

    id = trace_event_raw_init(call);

    if (id < 0) {
        free_syscall_print_fmt(call);
        return id;
    }

    return id;
#endif

    PANIC("");
}

static struct list_head *
syscall_get_enter_fields(struct trace_event_call *call)
{
    struct syscall_metadata *entry = call->data;

    return &entry->enter_fields;
}

static enum print_line_t
print_syscall_enter(struct trace_iterator *iter, int flags,
            struct trace_event *event)
{
    PANIC("");
}

static enum print_line_t
print_syscall_exit(struct trace_iterator *iter, int flags,
           struct trace_event *event)
{
    PANIC("");
}

static int syscall_enter_register(struct trace_event_call *event,
                 enum trace_reg type, void *data)
{
    PANIC("");
}

static int __init syscall_enter_define_fields(struct trace_event_call *call)
{
    PANIC("");
}

static int syscall_exit_register(struct trace_event_call *event,
                 enum trace_reg type, void *data)
{
    PANIC("");
}

static struct trace_event_fields __refdata syscall_enter_fields_array[] = {
    SYSCALL_FIELD(int, __syscall_nr),
    { .type = TRACE_FUNCTION_TYPE,
      .define_fields = syscall_enter_define_fields },
    {}
};

struct trace_event_functions enter_syscall_print_funcs = {
    .trace      = print_syscall_enter,
};

struct trace_event_functions exit_syscall_print_funcs = {
    .trace      = print_syscall_exit,
};

struct trace_event_class __refdata event_class_syscall_enter = {
    .system     = "syscalls",
    .reg        = syscall_enter_register,
    .fields_array   = syscall_enter_fields_array,
    .get_fields = syscall_get_enter_fields,
    .raw_init   = init_syscall_trace,
};

struct trace_event_class __refdata event_class_syscall_exit = {
    .system     = "syscalls",
    .reg        = syscall_exit_register,
    .fields_array   = (struct trace_event_fields[]){
        SYSCALL_FIELD(int, __syscall_nr),
        SYSCALL_FIELD(long, ret),
        {}
    },
    .fields     = LIST_HEAD_INIT(event_class_syscall_exit.fields),
    .raw_init   = init_syscall_trace,
};

void __init init_ftrace_syscalls(void)
{
#if 0
    struct syscall_metadata *meta;
    unsigned long addr;
    int i;
    void *ret;

    if (!IS_ENABLED(CONFIG_HAVE_SPARSE_SYSCALL_NR)) {
        syscalls_metadata = kcalloc(NR_syscalls,
                    sizeof(*syscalls_metadata),
                    GFP_KERNEL);
        if (!syscalls_metadata) {
            WARN_ON(1);
            return;
        }
    }

    for (i = 0; i < NR_syscalls; i++) {
        addr = arch_syscall_addr(i);
        meta = find_syscall_meta(addr);
        if (!meta)
            continue;

        meta->syscall_nr = i;

        if (!IS_ENABLED(CONFIG_HAVE_SPARSE_SYSCALL_NR)) {
            syscalls_metadata[i] = meta;
        } else {
            ret = xa_store(&syscalls_metadata_sparse, i, meta,
                    GFP_KERNEL);
            WARN(xa_is_err(ret),
                "Syscall memory allocation failed\n");
        }

    }
#endif
    pr_notice("%s: No impl.", __func__);
}
