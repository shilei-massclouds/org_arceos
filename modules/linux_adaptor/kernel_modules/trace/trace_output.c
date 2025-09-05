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

static int
lat_print_generic(struct trace_seq *s, struct trace_entry *entry, int cpu)
{
    char comm[TASK_COMM_LEN];

    trace_find_cmdline(entry->pid, comm);

    trace_seq_printf(s, "%8.8s-%-7d %3d",
             comm, entry->pid, cpu);

    return trace_print_lat_fmt(s, entry);
}

/**
 * trace_print_lat_fmt - print the irq, preempt and lockdep fields
 * @s: trace seq struct to write to
 * @entry: The trace entry field from the ring buffer
 *
 * Prints the generic fields of irqs off, in hard or softirq, preempt
 * count.
 */
int trace_print_lat_fmt(struct trace_seq *s, struct trace_entry *entry)
{
    char hardsoft_irq;
    char need_resched;
    char irqs_off;
    int hardirq;
    int softirq;
    int bh_off;
    int nmi;

    nmi = entry->flags & TRACE_FLAG_NMI;
    hardirq = entry->flags & TRACE_FLAG_HARDIRQ;
    softirq = entry->flags & TRACE_FLAG_SOFTIRQ;
    bh_off = entry->flags & TRACE_FLAG_BH_OFF;

    irqs_off =
        (entry->flags & TRACE_FLAG_IRQS_OFF && bh_off) ? 'D' :
        (entry->flags & TRACE_FLAG_IRQS_OFF) ? 'd' :
        bh_off ? 'b' :
        (entry->flags & TRACE_FLAG_IRQS_NOSUPPORT) ? 'X' :
        '.';

    switch (entry->flags & (TRACE_FLAG_NEED_RESCHED |
                TRACE_FLAG_PREEMPT_RESCHED)) {
    case TRACE_FLAG_NEED_RESCHED | TRACE_FLAG_PREEMPT_RESCHED:
        need_resched = 'N';
        break;
    case TRACE_FLAG_NEED_RESCHED:
        need_resched = 'n';
        break;
    case TRACE_FLAG_PREEMPT_RESCHED:
        need_resched = 'p';
        break;
    default:
        need_resched = '.';
        break;
    }

    hardsoft_irq =
        (nmi && hardirq)     ? 'Z' :
        nmi                  ? 'z' :
        (hardirq && softirq) ? 'H' :
        hardirq              ? 'h' :
        softirq              ? 's' :
                               '.' ;

    trace_seq_printf(s, "%c%c%c",
             irqs_off, need_resched, hardsoft_irq);

    if (entry->preempt_count & 0xf)
        trace_seq_printf(s, "%x", entry->preempt_count & 0xf);
    else
        trace_seq_putc(s, '.');

    if (entry->preempt_count & 0xf0)
        trace_seq_printf(s, "%x", entry->preempt_count >> 4);
    else
        trace_seq_putc(s, '.');

    return !trace_seq_has_overflowed(s);
}

#undef MARK
#define MARK(v, s) {.val = v, .sym = s}
/* trace overhead mark */
static const struct trace_mark {
    unsigned long long  val; /* unit: nsec */
    char            sym;
} mark[] = {
    MARK(1000000000ULL  , '$'), /* 1 sec */
    MARK(100000000ULL   , '@'), /* 100 msec */
    MARK(10000000ULL    , '*'), /* 10 msec */
    MARK(1000000ULL     , '#'), /* 1000 usecs */
    MARK(100000ULL      , '!'), /* 100 usecs */
    MARK(10000ULL       , '+'), /* 10 usecs */
};
#undef MARK

char trace_find_mark(unsigned long long d)
{
    int i;
    int size = ARRAY_SIZE(mark);

    for (i = 0; i < size; i++) {
        if (d > mark[i].val)
            break;
    }

    return (i == size) ? ' ' : mark[i].sym;
}

static int
lat_print_timestamp(struct trace_iterator *iter, u64 next_ts)
{
    struct trace_array *tr = iter->tr;
    unsigned long verbose = tr->trace_flags & TRACE_ITER_VERBOSE;
    unsigned long in_ns = iter->iter_flags & TRACE_FILE_TIME_IN_NS;
    unsigned long long abs_ts = iter->ts - iter->array_buffer->time_start;
    unsigned long long rel_ts = next_ts - iter->ts;
    struct trace_seq *s = &iter->seq;

    if (in_ns) {
        abs_ts = ns2usecs(abs_ts);
        rel_ts = ns2usecs(rel_ts);
    }

    if (verbose && in_ns) {
        unsigned long abs_usec = do_div(abs_ts, USEC_PER_MSEC);
        unsigned long abs_msec = (unsigned long)abs_ts;
        unsigned long rel_usec = do_div(rel_ts, USEC_PER_MSEC);
        unsigned long rel_msec = (unsigned long)rel_ts;

        trace_seq_printf(
            s, "[%08llx] %ld.%03ldms (+%ld.%03ldms): ",
            ns2usecs(iter->ts),
            abs_msec, abs_usec,
            rel_msec, rel_usec);

    } else if (verbose && !in_ns) {
        trace_seq_printf(
            s, "[%016llx] %lld (+%lld): ",
            iter->ts, abs_ts, rel_ts);

    } else if (!verbose && in_ns) {
        trace_seq_printf(
            s, " %4lldus%c: ",
            abs_ts,
            trace_find_mark(rel_ts * NSEC_PER_USEC));

    } else { /* !verbose && !in_ns */
        trace_seq_printf(s, " %4lld: ", abs_ts);
    }

    return !trace_seq_has_overflowed(s);
}

int trace_print_lat_context(struct trace_iterator *iter)
{
    struct trace_entry *entry, *next_entry;
    struct trace_array *tr = iter->tr;
    struct trace_seq *s = &iter->seq;
    unsigned long verbose = (tr->trace_flags & TRACE_ITER_VERBOSE);
    u64 next_ts;

    next_entry = trace_find_next_entry(iter, NULL, &next_ts);
    if (!next_entry)
        next_ts = iter->ts;

    /* trace_find_next_entry() may change iter->ent */
    entry = iter->ent;

    if (verbose) {
        char comm[TASK_COMM_LEN];

        trace_find_cmdline(entry->pid, comm);

        trace_seq_printf(
            s, "%16s %7d %3d %d %08x %08lx ",
            comm, entry->pid, iter->cpu, entry->flags,
            entry->preempt_count & 0xf, iter->idx);
    } else {
        lat_print_generic(s, entry, iter->cpu);
    }

    lat_print_timestamp(iter, next_ts);

    return !trace_seq_has_overflowed(s);
}

enum print_line_t print_event_fields(struct trace_iterator *iter,
                     struct trace_event *event)
{
    struct trace_event_call *call;
    struct list_head *head;

    lockdep_assert_held_read(&trace_event_sem);

#if 0
    /* ftrace defined events have separate call structures */
    if (event->type <= __TRACE_LAST_TYPE) {
        bool found = false;

        list_for_each_entry(call, &ftrace_events, list) {
            if (call->event.type == event->type) {
                found = true;
                break;
            }
            /* No need to search all events */
            if (call->event.type > __TRACE_LAST_TYPE)
                break;
        }
        if (!found) {
            trace_seq_printf(&iter->seq, "UNKNOWN TYPE %d\n", event->type);
            goto out;
        }
    } else {
        call = container_of(event, struct trace_event_call, event);
    }
    head = trace_get_fields(call);

    trace_seq_printf(&iter->seq, "%s:", trace_event_name(call));

    if (head && !list_empty(head))
        print_fields(iter, call, head);
    else
        trace_seq_puts(&iter->seq, "No fields found\n");
#endif

 out:
    PANIC("");
    return trace_handle_return(&iter->seq);
}

int trace_raw_output_prep(struct trace_iterator *iter,
              struct trace_event *trace_event)
{
    struct trace_event_call *event;
    struct trace_seq *s = &iter->seq;
    struct trace_seq *p = &iter->tmp_seq;
    struct trace_entry *entry;

    event = container_of(trace_event, struct trace_event_call, event);
    entry = iter->ent;

    if (entry->type != event->event.type) {
        WARN_ON_ONCE(1);
        return TRACE_TYPE_UNHANDLED;
    }

    trace_seq_init(p);
    trace_seq_printf(s, "%s: ", trace_event_name(event));

    return trace_handle_return(s);
}

void trace_event_printf(struct trace_iterator *iter, const char *fmt, ...)
{
    struct trace_seq *s = &iter->seq;
    va_list ap;

    if (ignore_event(iter))
        return;

    va_start(ap, fmt);
    trace_seq_vprintf(s, trace_event_format(iter, fmt), ap);
    va_end(ap);
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
