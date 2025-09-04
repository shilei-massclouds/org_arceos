#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/sched/clock.h>
#include <linux/sched/mm.h>
#include <linux/idr.h>

#include "trace_output.h"
#include "../adaptor.h"

/* must be a power of 2 */
#define EVENT_HASHSIZE  128

DECLARE_RWSEM(trace_event_sem);

static struct hlist_head event_hash[EVENT_HASHSIZE] __read_mostly;

/**
 * ftrace_find_event - find a registered event
 * @type: the type of event to look for
 *
 * Returns an event of type @type otherwise NULL
 * Called with trace_event_read_lock() held.
 */
struct trace_event *ftrace_find_event(int type)
{
    struct trace_event *event;
    unsigned key;

    key = type & (EVENT_HASHSIZE - 1);

    hlist_for_each_entry(event, &event_hash[key], node) {
        if (event->type == type)
            return event;
    }

    return NULL;
}

static DEFINE_IDA(trace_event_ida);

static void free_trace_event_type(int type)
{
    if (type >= __TRACE_LAST_TYPE)
        ida_free(&trace_event_ida, type);
}

static int alloc_trace_event_type(void)
{
    int next;

    /* Skip static defined type numbers */
    next = ida_alloc_range(&trace_event_ida, __TRACE_LAST_TYPE,
                   TRACE_EVENT_TYPE_MAX, GFP_KERNEL);
    if (next < 0)
        return 0;
    return next;
}

enum print_line_t trace_nop_print(struct trace_iterator *iter, int flags,
                  struct trace_event *event)
{
    printk("%s: ...\n", __func__);
    trace_seq_printf(&iter->seq, "type: %d\n", iter->ent->type);

    return trace_handle_return(&iter->seq);
}

/**
 * register_trace_event - register output for an event type
 * @event: the event type to register
 *
 * Event types are stored in a hash and this hash is used to
 * find a way to print an event. If the @event->type is set
 * then it will use that type, otherwise it will assign a
 * type to use.
 *
 * If you assign your own type, please make sure it is added
 * to the trace_type enum in trace.h, to avoid collisions
 * with the dynamic types.
 *
 * Returns the event type number or zero on error.
 */
int register_trace_event(struct trace_event *event)
{
    unsigned key;
    int ret = 0;

    down_write(&trace_event_sem);

    if (WARN_ON(!event))
        goto out;

    if (WARN_ON(!event->funcs))
        goto out;

    if (!event->type) {
        event->type = alloc_trace_event_type();
        if (!event->type)
            goto out;
    } else if (WARN(event->type > __TRACE_LAST_TYPE,
            "Need to add type to trace.h")) {
        goto out;
    } else {
        /* Is this event already used */
        if (ftrace_find_event(event->type))
            goto out;
    }

    if (event->funcs->trace == NULL)
        event->funcs->trace = trace_nop_print;
    if (event->funcs->raw == NULL)
        event->funcs->raw = trace_nop_print;
    if (event->funcs->hex == NULL)
        event->funcs->hex = trace_nop_print;
    if (event->funcs->binary == NULL)
        event->funcs->binary = trace_nop_print;

    key = event->type & (EVENT_HASHSIZE - 1);

    hlist_add_head(&event->node, &event_hash[key]);

    ret = event->type;
 out:
    up_write(&trace_event_sem);

    return ret;
}
