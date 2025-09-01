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

static int __init init_syscall_trace(struct trace_event_call *call)
{
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
