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

/*
 * printk is set to max of 1024, we really don't need it that big.
 * Nothing should be printing 1000 characters anyway.
 */
#define TRACE_MAX_PRINT     1000

/*
 * Define here KERN_TRACE so that we have one place to modify
 * it if we decide to change what log level the ftrace dump
 * should be at.
 */
#define KERN_TRACE      KERN_EMERG

/* trace_flags holds trace_options default values */
#define TRACE_DEFAULT_FLAGS                     \
    (FUNCTION_DEFAULT_FLAGS |                   \
     TRACE_ITER_PRINT_PARENT | TRACE_ITER_PRINTK |          \
     TRACE_ITER_ANNOTATE | TRACE_ITER_CONTEXT_INFO |        \
     TRACE_ITER_RECORD_CMD | TRACE_ITER_OVERWRITE |         \
     TRACE_ITER_IRQ_INFO | TRACE_ITER_MARKERS |         \
     TRACE_ITER_HASH_PTR | TRACE_ITER_TRACE_PRINTK)

/*
 * trace_buf_size is the size in bytes that is allocated
 * for a buffer. Note, the number of bytes is always rounded
 * to page size.
 *
 * This number is purposely set to a low number of 16384.
 * If the dump on oops happens, it will be much appreciated
 * to not have to wait for all that output. Anyway this can be
 * boot time and run time configurable.
 */
#define TRACE_BUF_SIZE_DEFAULT  1441792UL /* 16384 * 88 (sizeof(entry)) */

static unsigned long        trace_buf_size = TRACE_BUF_SIZE_DEFAULT;

static int boot_instance_index;

/* trace_types holds a link list of available tracers. */
static struct tracer        *trace_types __read_mostly;

static char *default_bootup_tracer;

static DEFINE_STATIC_KEY_FALSE(tracepoint_printk_key);
static DEFINE_STATIC_KEY_FALSE(trace_event_exports_enabled);

/* For tracers that don't implement custom flags */
static struct tracer_opt dummy_tracer_opt[] = {
    { }
};

#define STATIC_TEMP_BUF_SIZE    128
static char static_temp_buf[STATIC_TEMP_BUF_SIZE] __aligned(4);

#define STATIC_FMT_BUF_SIZE 128
static char static_fmt_buf[STATIC_FMT_BUF_SIZE];

static struct {
    u64 (*func)(void);
    const char *name;
    int in_ns;      /* is this clock in nanoseconds? */
} trace_clocks[] = {
    { trace_clock_local,        "local",    1 },
    { trace_clock_global,       "global",   1 },
    { trace_clock_counter,      "counter",  0 },
    { trace_clock_jiffies,      "uptime",   0 },
    { trace_clock,          "perf",     1 },
    { ktime_get_mono_fast_ns,   "mono",     1 },
    { ktime_get_raw_fast_ns,    "mono_raw", 1 },
    { ktime_get_boot_fast_ns,   "boot",     1 },
    { ktime_get_tai_fast_ns,    "tai",      1 },
    ARCH_TRACE_CLOCKS
};

static int
dummy_set_flag(struct trace_array *tr, u32 old_flags, u32 bit, int set)
{
    return 0;
}

/*
 * To prevent the comm cache from being overwritten when no
 * tracing is active, only save the comm when a trace event
 * occurred.
 */
DEFINE_PER_CPU(bool, trace_taskinfo_save);

/*
 * trace_types_lock is used to protect the trace_types list.
 */
DEFINE_MUTEX(trace_types_lock);

static char *trace_boot_clock __initdata;

static struct trace_buffer *temp_buffer;

cpumask_var_t __read_mostly tracing_buffer_mask;

static char trace_boot_options_buf[MAX_TRACER_SIZE] __initdata;

/*
 * Kill all tracing for good (never come back).
 * It is initialized to 1 but will turn to zero if the initialization
 * of the tracer is successful. But that is the only place that sets
 * this back to zero.
 */
static int tracing_disabled = 1;

LIST_HEAD(ftrace_trace_arrays);

/*
 * The global_trace is the descriptor that holds the top-level tracing
 * buffers for the live tracing.
 */
static struct trace_array global_trace = {
    .trace_flags = TRACE_DEFAULT_FLAGS,
};

static void ftrace_exports(struct ring_buffer_event *event, int flag)
{
    PANIC("");
}

__init static void enable_instances(void)
{
    PANIC("");
}

static bool tracer_options_updated;

static void
create_trace_option_files(struct trace_array *tr, struct tracer *tracer)
{
    PANIC("");
}

static void add_tracer_options(struct trace_array *tr, struct tracer *t)
{
    /* Only enable if the directory has been created already. */
    if (!tr->dir)
        return;

    /* Only create trace option files after update_tracer_options finish */
    if (!tracer_options_updated)
        return;

    create_trace_option_files(tr, t);
}

static void set_buffer_entries(struct array_buffer *buf, unsigned long val)
{
    int cpu;

    for_each_tracing_cpu(cpu)
        per_cpu_ptr(buf->data, cpu)->entries = val;
}

static int
allocate_trace_buffer(struct trace_array *tr, struct array_buffer *buf, int size)
{
    enum ring_buffer_flags rb_flags;

    rb_flags = tr->trace_flags & TRACE_ITER_OVERWRITE ? RB_FL_OVERWRITE : 0;

    buf->tr = tr;

    if (tr->range_addr_start && tr->range_addr_size) {
        buf->buffer = ring_buffer_alloc_range(size, rb_flags, 0,
                              tr->range_addr_start,
                              tr->range_addr_size);

        ring_buffer_last_boot_delta(buf->buffer,
                        &tr->text_delta, &tr->data_delta);
        /*
         * This is basically the same as a mapped buffer,
         * with the same restrictions.
         */
        tr->mapped++;
    } else {
        buf->buffer = ring_buffer_alloc(size, rb_flags);
    }
    if (!buf->buffer)
        return -ENOMEM;

    buf->data = alloc_percpu(struct trace_array_cpu);
    if (!buf->data) {
        ring_buffer_free(buf->buffer);
        buf->buffer = NULL;
        return -ENOMEM;
    }

    /* Allocate the first page for all buffers */
    set_buffer_entries(&tr->array_buffer,
               ring_buffer_size(tr->array_buffer.buffer, 0));

    return 0;
}

static int allocate_trace_buffers(struct trace_array *tr, int size)
{
    int ret;

    ret = allocate_trace_buffer(tr, &tr->array_buffer, size);
    if (ret)
        return ret;

#ifdef CONFIG_TRACER_MAX_TRACE
    /* Fix mapped buffer trace arrays do not have snapshot buffers */
    if (tr->range_addr_start)
        return 0;

    ret = allocate_trace_buffer(tr, &tr->max_buffer,
                    allocate_snapshot ? size : 1);
    if (MEM_FAIL(ret, "Failed to allocate trace buffer\n")) {
        free_trace_buffer(&tr->array_buffer);
        return -ENOMEM;
    }
    tr->allocated_snapshot = allocate_snapshot;

    allocate_snapshot = false;
#endif

    return 0;
}

static void init_trace_flags_index(struct trace_array *tr)
{
    int i;

    /* Used by the trace options files */
    for (i = 0; i < TRACE_FLAGS_MAX_SIZE; i++)
        tr->trace_flags_index[i] = i;
}

static void __init apply_trace_boot_options(void)
{
    char *buf = trace_boot_options_buf;
    char *option;

    while (true) {
        option = strsep(&buf, ",");

        if (!option)
            break;

        if (*option)
            trace_set_options(&global_trace, option);

        /* Put back the comma to allow this to be called again */
        if (buf)
            *(buf - 1) = ',';
    }
}

__init static int tracer_alloc_buffers(void)
{
    int ring_buf_size;
    int ret = -ENOMEM;

    /*
    if (security_locked_down(LOCKDOWN_TRACEFS)) {
        pr_warn("Tracing disabled due to lockdown\n");
        return -EPERM;
    }
    */

    /*
     * Make sure we don't accidentally add more trace options
     * than we have bits for.
     */
    BUILD_BUG_ON(TRACE_ITER_LAST_BIT > TRACE_FLAGS_MAX_SIZE);

    if (!alloc_cpumask_var(&tracing_buffer_mask, GFP_KERNEL))
        goto out;

    if (!alloc_cpumask_var(&global_trace.tracing_cpumask, GFP_KERNEL))
        goto out_free_buffer_mask;

#if 0
    /* Only allocate trace_printk buffers if a trace_printk exists */
    if (&__stop___trace_bprintk_fmt != &__start___trace_bprintk_fmt)
        /* Must be called before global_trace.buffer is allocated */
        trace_printk_init_buffers();
#endif

    /* To save memory, keep the ring buffer size to its minimum */
    if (global_trace.ring_buffer_expanded)
        ring_buf_size = trace_buf_size;
    else
        ring_buf_size = 1;

    cpumask_copy(tracing_buffer_mask, cpu_possible_mask);
    cpumask_copy(global_trace.tracing_cpumask, cpu_all_mask);

    raw_spin_lock_init(&global_trace.start_lock);

#if 0
    /*
     * The prepare callbacks allocates some memory for the ring buffer. We
     * don't free the buffer if the CPU goes down. If we were to free
     * the buffer, then the user would lose any trace that was in the
     * buffer. The memory will be removed once the "instance" is removed.
     */
    ret = cpuhp_setup_state_multi(CPUHP_TRACE_RB_PREPARE,
                      "trace/RB:prepare", trace_rb_cpu_prepare,
                      NULL);
    if (ret < 0)
        goto out_free_cpumask;
#endif
    pr_notice("%s: No impl.", __func__);

    /* Used for event triggers */
    ret = -ENOMEM;
    temp_buffer = ring_buffer_alloc(PAGE_SIZE, RB_FL_OVERWRITE);
    if (!temp_buffer)
        goto out_rm_hp_state;

    if (trace_create_savedcmd() < 0)
        goto out_free_temp_buffer;

    if (!zalloc_cpumask_var(&global_trace.pipe_cpumask, GFP_KERNEL))
        goto out_free_savedcmd;

    /* TODO: make the number of buffers hot pluggable with CPUS */
    if (allocate_trace_buffers(&global_trace, ring_buf_size) < 0) {
        MEM_FAIL(1, "tracer: failed to allocate ring buffer!\n");
        goto out_free_pipe_cpumask;
    }
    if (global_trace.buffer_disabled)
        tracing_off();

    if (trace_boot_clock) {
        ret = tracing_set_clock(&global_trace, trace_boot_clock);
        if (ret < 0)
            pr_warn("Trace clock %s not defined, going back to default\n",
                trace_boot_clock);
    }

    /*
     * register_tracer() might reference current_trace, so it
     * needs to be set before we register anything. This is
     * just a bootstrap of current_trace anyway.
     */
    global_trace.current_trace = &nop_trace;

    global_trace.max_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
#ifdef CONFIG_TRACER_MAX_TRACE
    spin_lock_init(&global_trace.snapshot_trigger_lock);
#endif
    ftrace_init_global_array_ops(&global_trace);

    init_trace_flags_index(&global_trace);

    register_tracer(&nop_trace);

    /* Function tracing may start here (via kernel command line) */
    init_function_trace();

    /* All seems OK, enable tracing */
    tracing_disabled = 0;

#if 0
    atomic_notifier_chain_register(&panic_notifier_list,
                       &trace_panic_notifier);

    register_die_notifier(&trace_die_notifier);
#endif

    global_trace.flags = TRACE_ARRAY_FL_GLOBAL;

    INIT_LIST_HEAD(&global_trace.systems);
    INIT_LIST_HEAD(&global_trace.events);
    INIT_LIST_HEAD(&global_trace.hist_vars);
    INIT_LIST_HEAD(&global_trace.err_log);
    list_add(&global_trace.list, &ftrace_trace_arrays);

    apply_trace_boot_options();

    //register_snapshot_cmd();

    return 0;

out_free_pipe_cpumask:
    free_cpumask_var(global_trace.pipe_cpumask);
out_free_savedcmd:
    trace_free_saved_cmdlines_buffer();
out_free_temp_buffer:
    ring_buffer_free(temp_buffer);
out_rm_hp_state:
    cpuhp_remove_multi_state(CPUHP_TRACE_RB_PREPARE);
out_free_cpumask:
    free_cpumask_var(global_trace.tracing_cpumask);
out_free_buffer_mask:
    free_cpumask_var(tracing_buffer_mask);
out:
    return ret;
}

static unsigned short migration_disable_value(void)
{
#if defined(CONFIG_SMP)
    return current->migration_disabled;
#else
    return 0;
#endif
}

unsigned int tracing_gen_ctx_irq_test(unsigned int irqs_status)
{
    unsigned int trace_flags = irqs_status;
    unsigned int pc;

    pc = preempt_count();

    if (pc & NMI_MASK)
        trace_flags |= TRACE_FLAG_NMI;
    if (pc & HARDIRQ_MASK)
        trace_flags |= TRACE_FLAG_HARDIRQ;
    if (in_serving_softirq())
        trace_flags |= TRACE_FLAG_SOFTIRQ;
    if (softirq_count() >> (SOFTIRQ_SHIFT + 1))
        trace_flags |= TRACE_FLAG_BH_OFF;

    if (tif_need_resched())
        trace_flags |= TRACE_FLAG_NEED_RESCHED;
    if (test_preempt_need_resched())
        trace_flags |= TRACE_FLAG_PREEMPT_RESCHED;
    return (trace_flags << 16) | (min_t(unsigned int, pc & 0xff, 0xf)) |
        (min_t(unsigned int, migration_disable_value(), 0xf)) << 4;
}

static __always_inline void
trace_event_setup(struct ring_buffer_event *event,
          int type, unsigned int trace_ctx)
{
    struct trace_entry *ent = ring_buffer_event_data(event);

    tracing_generic_entry_update(ent, type, trace_ctx);
}

static __always_inline struct ring_buffer_event *
__trace_buffer_lock_reserve(struct trace_buffer *buffer,
              int type,
              unsigned long len,
              unsigned int trace_ctx)
{
    struct ring_buffer_event *event;

    printk("%s: type(%d) len(%lu)\n", __func__, type, len);
    event = ring_buffer_lock_reserve(buffer, len);
    if (event != NULL)
        trace_event_setup(event, type, trace_ctx);

    return event;
}

struct ring_buffer_event *
trace_event_buffer_lock_reserve(struct trace_buffer **current_rb,
              struct trace_event_file *trace_file,
              int type, unsigned long len,
              unsigned int trace_ctx)
{
    struct ring_buffer_event *entry;
    struct trace_array *tr = trace_file->tr;
    int val;


    *current_rb = tr->array_buffer.buffer;

    if (!tr->no_filter_buffering_ref &&
        (trace_file->flags & (EVENT_FILE_FL_SOFT_DISABLED | EVENT_FILE_FL_FILTERED))) {

        PANIC("stage1");
    }


    entry = __trace_buffer_lock_reserve(*current_rb, type, len,
                        trace_ctx);
    /*
     * If tracing is off, but we have triggers enabled
     * we still need to look at the event data. Use the temp_buffer
     * to store the trace event for the trigger to use. It's recursive
     * safe and will not be recorded anywhere.
     */
    if (!entry && trace_file->flags & EVENT_FILE_FL_TRIGGER_COND) {
        *current_rb = temp_buffer;
        entry = __trace_buffer_lock_reserve(*current_rb, type, len,
                            trace_ctx);
    }
    return entry;
}

static inline int do_run_tracer_selftest(struct tracer *type)
{
    return 0;
}

static void output_printk(struct trace_event_buffer *fbuffer)
{
    PANIC("");
}

void trace_event_buffer_commit(struct trace_event_buffer *fbuffer)
{
    enum event_trigger_type tt = ETT_NONE;
    struct trace_event_file *file = fbuffer->trace_file;

    if (__event_trigger_test_discard(file, fbuffer->buffer, fbuffer->event,
            fbuffer->entry, &tt))
        goto discard;

    if (static_key_false(&tracepoint_printk_key.key))
        output_printk(fbuffer);

    if (static_branch_unlikely(&trace_event_exports_enabled))
        ftrace_exports(fbuffer->event, TRACE_EXPORT_EVENT);

    trace_buffer_unlock_commit_regs(file->tr, fbuffer->buffer,
            fbuffer->event, fbuffer->trace_ctx, fbuffer->regs);

discard:
    if (tt)
        event_triggers_post_call(file, tt);

}

static __always_inline void
__buffer_unlock_commit(struct trace_buffer *buffer, struct ring_buffer_event *event)
{
    __this_cpu_write(trace_taskinfo_save, true);

    /* If this is the temp buffer, we need to commit fully */
    if (this_cpu_read(trace_buffered_event) == event) {
        /* Length is in event->array[0] */
        ring_buffer_write(buffer, event->array[0], &event->array[1]);
        /* Release the temp buffer */
        this_cpu_dec(trace_buffered_event_cnt);
        /* ring_buffer_unlock_commit() enables preemption */
        preempt_enable_notrace();
    } else
        ring_buffer_unlock_commit(buffer);
}

static void __ftrace_trace_stack(struct trace_array *tr,
                 struct trace_buffer *buffer,
                 unsigned int trace_ctx,
                 int skip, struct pt_regs *regs)
{
    PANIC("");
}

static inline void ftrace_trace_stack(struct trace_array *tr,
                      struct trace_buffer *buffer,
                      unsigned int trace_ctx,
                      int skip, struct pt_regs *regs)
{
    if (!(tr->trace_flags & TRACE_ITER_STACKTRACE))
        return;

    __ftrace_trace_stack(tr, buffer, trace_ctx, skip, regs);
}

static void
ftrace_trace_userstack(struct trace_array *tr,
               struct trace_buffer *buffer, unsigned int trace_ctx)
{
    struct trace_event_call *call = &event_user_stack;
    struct ring_buffer_event *event;
    struct userstack_entry *entry;

    if (!(tr->trace_flags & TRACE_ITER_USERSTACKTRACE))
        return;


    PANIC("");
}

/*
 * Skip 3:
 *
 *   trace_buffer_unlock_commit_regs()
 *   trace_event_buffer_commit()
 *   trace_event_raw_event_xxx()
 */
# define STACK_SKIP 3

void trace_buffer_unlock_commit_regs(struct trace_array *tr,
                     struct trace_buffer *buffer,
                     struct ring_buffer_event *event,
                     unsigned int trace_ctx,
                     struct pt_regs *regs)
{
    __buffer_unlock_commit(buffer, event);

    /*
     * If regs is not set, then skip the necessary functions.
     * Note, we can still get here via blktrace, wakeup tracer
     * and mmiotrace, but that's ok if they lose a function or
     * two. They are not that meaningful.
     */
    ftrace_trace_stack(tr, buffer, trace_ctx, regs ? 0 : STACK_SKIP, regs);
    ftrace_trace_userstack(tr, buffer, trace_ctx);
}

/**
 * register_tracer - register a tracer with the ftrace system.
 * @type: the plugin for the tracer
 *
 * Register a new plugin tracer.
 */
int __init register_tracer(struct tracer *type)
{
    struct tracer *t;
    int ret = 0;

    if (!type->name) {
        pr_info("Tracer must have a name\n");
        return -1;
    }

    if (strlen(type->name) >= MAX_TRACER_SIZE) {
        pr_info("Tracer has a name longer than %d\n", MAX_TRACER_SIZE);
        return -1;
    }

#if 0
    if (security_locked_down(LOCKDOWN_TRACEFS)) {
        pr_warn("Can not register tracer %s due to lockdown\n",
               type->name);
        return -EPERM;
    }
#endif

    printk("%s: ------------------ [%s]\n", __func__, type->name);
    mutex_lock(&trace_types_lock);

    for (t = trace_types; t; t = t->next) {
        if (strcmp(type->name, t->name) == 0) {
            /* already found */
            pr_info("Tracer %s already registered\n",
                type->name);
            ret = -1;
            goto out;
        }
    }

    if (!type->set_flag)
        type->set_flag = &dummy_set_flag;
    if (!type->flags) {
        /*allocate a dummy tracer_flags*/
        type->flags = kmalloc(sizeof(*type->flags), GFP_KERNEL);
        if (!type->flags) {
            ret = -ENOMEM;
            goto out;
        }
        type->flags->val = 0;
        type->flags->opts = dummy_tracer_opt;
    } else
        if (!type->flags->opts)
            type->flags->opts = dummy_tracer_opt;

    /* store the tracer for __set_tracer_option */
    type->flags->trace = type;

    ret = do_run_tracer_selftest(type);
    if (ret < 0)
        goto out;

    type->next = trace_types;
    trace_types = type;
    add_tracer_options(&global_trace, type);

 out:
    mutex_unlock(&trace_types_lock);

    if (ret || !default_bootup_tracer)
        goto out_unlock;

#if 0
    if (strncmp(default_bootup_tracer, type->name, MAX_TRACER_SIZE))
        goto out_unlock;

    printk("%s: ------------------ [%s] step2\n", __func__, type->name);
    printk(KERN_INFO "Starting tracer '%s'\n", type->name);
    /* Do we want this tracer to start on bootup? */
    tracing_set_tracer(&global_trace, type->name);
    default_bootup_tracer = NULL;

    apply_trace_boot_options();

    /* disable other selftests, since this will break it. */
    disable_tracing_selftest("running a tracer");
#endif

    PANIC("");
 out_unlock:
    return ret;
}

static void trace_init_iter(struct trace_iterator *iter, struct trace_array *tr)
{
    iter->tr = tr;
    iter->trace = iter->tr->current_trace;
    iter->cpu_file = RING_BUFFER_ALL_CPUS;
    iter->array_buffer = &tr->array_buffer;

    if (iter->trace && iter->trace->open)
        iter->trace->open(iter);

    /* Annotate start of buffers if we had overruns */
    if (ring_buffer_overruns(iter->array_buffer->buffer))
        iter->iter_flags |= TRACE_FILE_ANNOTATE;

    /* Output in nanoseconds only if we are using a clock in nanoseconds. */
    if (trace_clocks[iter->tr->clock_id].in_ns)
        iter->iter_flags |= TRACE_FILE_TIME_IN_NS;

    /* Can not use kmalloc for iter.temp and iter.fmt */
    iter->temp = static_temp_buf;
    iter->temp_size = STATIC_TEMP_BUF_SIZE;
    iter->fmt = static_fmt_buf;
    iter->fmt_size = STATIC_FMT_BUF_SIZE;
}

void tracer_tracing_off(struct trace_array *tr)
{
    if (tr->array_buffer.buffer)
        ring_buffer_record_off(tr->array_buffer.buffer);
    /*
     * This flag is looked at when buffers haven't been allocated
     * yet, or by some tracers (like irqsoff), that just want to
     * know if the ring buffer has been disabled, but it can handle
     * races of where it gets disabled but we still do a record.
     * As the check is in the fast path of the tracers, it is more
     * important to be fast than accurate.
     */
    tr->buffer_disabled = 1;
    /* Make the flag seen by readers */
    smp_wmb();
}

static void test_cpu_buff_start(struct trace_iterator *iter)
{
    struct trace_seq *s = &iter->seq;
    struct trace_array *tr = iter->tr;

    if (!(tr->trace_flags & TRACE_ITER_ANNOTATE))
        return;

    if (!(iter->iter_flags & TRACE_FILE_ANNOTATE))
        return;

    if (cpumask_available(iter->started) &&
        cpumask_test_cpu(iter->cpu, iter->started))
        return;

    if (per_cpu_ptr(iter->array_buffer->data, iter->cpu)->skipped_entries)
        return;

    if (cpumask_available(iter->started))
        cpumask_set_cpu(iter->cpu, iter->started);

    /* Don't print started cpu buffer for the first entry of the trace */
    if (iter->idx > 1)
        trace_seq_printf(s, "##### CPU %u buffer started ####\n",
                iter->cpu);
}

static enum print_line_t print_trace_fmt(struct trace_iterator *iter)
{
    struct trace_array *tr = iter->tr;
    struct trace_seq *s = &iter->seq;
    unsigned long sym_flags = (tr->trace_flags & TRACE_ITER_SYM_MASK);
    struct trace_entry *entry;
    struct trace_event *event;

    entry = iter->ent;

    test_cpu_buff_start(iter);

    event = ftrace_find_event(entry->type);

    if (tr->trace_flags & TRACE_ITER_CONTEXT_INFO) {
        if (iter->iter_flags & TRACE_FILE_LAT_FMT)
            trace_print_lat_context(iter);
        else
            trace_print_context(iter);
    }

    if (trace_seq_has_overflowed(s))
        return TRACE_TYPE_PARTIAL_LINE;

    if (event) {
        if (tr->trace_flags & TRACE_ITER_FIELDS)
            return print_event_fields(iter, event);
        /*
         * For TRACE_EVENT() events, the print_fmt is not
         * safe to use if the array has delta offsets
         * Force printing via the fields.
         */
        if ((tr->text_delta || tr->data_delta) &&
            event->type > __TRACE_LAST_TYPE)
            return print_event_fields(iter, event);

        return event->funcs->trace(iter, sym_flags, event);
    }

#if 0
    trace_seq_printf(s, "Unknown type %d\n", entry->type);

    return trace_handle_return(s);

#endif
    PANIC("");
}

/* Returns true if the string is safe to dereference from an event */
static bool trace_safe_str(struct trace_iterator *iter, const char *str)
{
    PANIC("");
}

/**
 * ignore_event - Check dereferenced fields while writing to the seq buffer
 * @iter: The iterator that holds the seq buffer and the event being printed
 *
 * At boot up, test_event_printk() will flag any event that dereferences
 * a string with "%s" that does exist in the ring buffer. It may still
 * be valid, as the string may point to a static string in the kernel
 * rodata that never gets freed. But if the string pointer is pointing
 * to something that was allocated, there's a chance that it can be freed
 * by the time the user reads the trace. This would cause a bad memory
 * access by the kernel and possibly crash the system.
 *
 * This function will check if the event has any fields flagged as needing
 * to be checked at runtime and perform those checks.
 *
 * If it is found that a field is unsafe, it will write into the @iter->seq
 * a message stating what was found to be unsafe.
 *
 * @return: true if the event is unsafe and should be ignored,
 *          false otherwise.
 */
bool ignore_event(struct trace_iterator *iter)
{
    struct ftrace_event_field *field;
    struct trace_event *trace_event;
    struct trace_event_call *event;
    struct list_head *head;
    struct trace_seq *seq;
    const void *ptr;

    trace_event = ftrace_find_event(iter->ent->type);

    seq = &iter->seq;

    if (!trace_event) {
        trace_seq_printf(seq, "EVENT ID %d NOT FOUND?\n", iter->ent->type);
        return true;
    }

    event = container_of(trace_event, struct trace_event_call, event);
    if (!(event->flags & TRACE_EVENT_FL_TEST_STR))
        return false;

    head = trace_get_fields(event);
    if (!head) {
        trace_seq_printf(seq, "FIELDS FOR EVENT '%s' NOT FOUND?\n",
                 trace_event_name(event));
        return true;
    }

    /* Offsets are from the iter->ent that points to the raw event */
    ptr = iter->ent;

    list_for_each_entry(field, head, link) {
        const char *str;
        bool good;

        if (!field->needs_test)
            continue;

        str = *(const char **)(ptr + field->offset);

        good = trace_safe_str(iter, str);

        /*
         * If you hit this warning, it is likely that the
         * trace event in question used %s on a string that
         * was saved at the time of the event, but may not be
         * around when the trace is read. Use __string(),
         * __assign_str() and __get_str() helpers in the TRACE_EVENT()
         * instead. See samples/trace_events/trace-events-sample.h
         * for reference.
         */
        if (WARN_ONCE(!good, "event '%s' has unsafe pointer field '%s'",
                  trace_event_name(event), field->name)) {
            trace_seq_printf(seq, "EVENT %s: HAS UNSAFE POINTER FIELD '%s'\n",
                     trace_event_name(event), field->name);
            return true;
        }
    }
    PANIC("");
    return false;
}

char *trace_iter_expand_format(struct trace_iterator *iter)
{
    char *tmp;

    /*
     * iter->tr is NULL when used with tp_printk, which makes
     * this get called where it is not safe to call krealloc().
     */
    if (!iter->tr || iter->fmt == static_fmt_buf)
        return NULL;

    tmp = krealloc(iter->fmt, iter->fmt_size + STATIC_FMT_BUF_SIZE,
               GFP_KERNEL);
    if (tmp) {
        iter->fmt_size += STATIC_FMT_BUF_SIZE;
        iter->fmt = tmp;
    }

    return tmp;
}

const char *trace_event_format(struct trace_iterator *iter, const char *fmt)
{
    const char *p, *new_fmt;
    char *q;

    if (WARN_ON_ONCE(!fmt))
        return fmt;

    if (!iter->tr || iter->tr->trace_flags & TRACE_ITER_HASH_PTR)
        return fmt;

    p = fmt;
    new_fmt = q = iter->fmt;
    while (*p) {
        if (unlikely(q - new_fmt + 3 > iter->fmt_size)) {
            if (!trace_iter_expand_format(iter))
                return fmt;

            q += iter->fmt - new_fmt;
            new_fmt = iter->fmt;
        }

        *q++ = *p++;

        /* Replace %p with %px */
        if (p[-1] == '%') {
            if (p[0] == '%') {
                *q++ = *p++;
            } else if (p[0] == 'p' && !isalnum(p[1])) {
                *q++ = *p++;
                *q++ = 'x';
            }
        }
    }
    *q = '\0';

    PANIC("");
    return new_fmt;
}


/*
 * Several functions return TRACE_TYPE_PARTIAL_LINE if the trace_seq
 * overflowed, and TRACE_TYPE_HANDLED otherwise. This helper function
 * simplifies those functions and keeps them in sync.
 */
enum print_line_t trace_handle_return(struct trace_seq *s)
{
    return trace_seq_has_overflowed(s) ?
        TRACE_TYPE_PARTIAL_LINE : TRACE_TYPE_HANDLED;
}

static enum print_line_t print_bin_fmt(struct trace_iterator *iter)
{
    PANIC("");
}

static enum print_line_t print_hex_fmt(struct trace_iterator *iter)
{
    PANIC("");
}

static enum print_line_t print_raw_fmt(struct trace_iterator *iter)
{
    PANIC("");
}

/*  Called with trace_event_read_lock() held. */
enum print_line_t print_trace_line(struct trace_iterator *iter)
{
    struct trace_array *tr = iter->tr;
    unsigned long trace_flags = tr->trace_flags;
    enum print_line_t ret;

    if (iter->lost_events) {
        if (iter->lost_events == (unsigned long)-1)
            trace_seq_printf(&iter->seq, "CPU:%d [LOST EVENTS]\n",
                     iter->cpu);
        else
            trace_seq_printf(&iter->seq, "CPU:%d [LOST %lu EVENTS]\n",
                     iter->cpu, iter->lost_events);
        if (trace_seq_has_overflowed(&iter->seq))
            return TRACE_TYPE_PARTIAL_LINE;
    }

    if (iter->trace && iter->trace->print_line) {
        ret = iter->trace->print_line(iter);
        if (ret != TRACE_TYPE_UNHANDLED)
            return ret;
    }

    if (iter->ent->type == TRACE_BPUTS &&
            trace_flags & TRACE_ITER_PRINTK &&
            trace_flags & TRACE_ITER_PRINTK_MSGONLY)
        return trace_print_bputs_msg_only(iter);

    if (iter->ent->type == TRACE_BPRINT &&
            trace_flags & TRACE_ITER_PRINTK &&
            trace_flags & TRACE_ITER_PRINTK_MSGONLY)
        return trace_print_bprintk_msg_only(iter);

    if (iter->ent->type == TRACE_PRINT &&
            trace_flags & TRACE_ITER_PRINTK &&
            trace_flags & TRACE_ITER_PRINTK_MSGONLY)
        return trace_print_printk_msg_only(iter);

    if (trace_flags & TRACE_ITER_BIN)
        return print_bin_fmt(iter);

    if (trace_flags & TRACE_ITER_HEX)
        return print_hex_fmt(iter);

    if (trace_flags & TRACE_ITER_RAW)
        return print_raw_fmt(iter);

    return print_trace_fmt(iter);
}

static void trace_iterator_increment(struct trace_iterator *iter)
{
    struct ring_buffer_iter *buf_iter = trace_buffer_iter(iter, iter->cpu);

    iter->idx++;
    if (buf_iter)
        ring_buffer_iter_advance(buf_iter);
}

static struct trace_entry *
peek_next_entry(struct trace_iterator *iter, int cpu, u64 *ts,
        unsigned long *lost_events)
{
    struct ring_buffer_event *event;
    struct ring_buffer_iter *buf_iter = trace_buffer_iter(iter, cpu);

    if (buf_iter) {
        event = ring_buffer_iter_peek(buf_iter, ts);
        if (lost_events)
            *lost_events = ring_buffer_iter_dropped(buf_iter) ?
                (unsigned long)-1 : 0;
    } else {
        event = ring_buffer_peek(iter->array_buffer->buffer, cpu, ts,
                     lost_events);
    }

    if (event) {
        iter->ent_size = ring_buffer_event_length(event);
        return ring_buffer_event_data(event);
    }
#if 0
    iter->ent_size = 0;
    return NULL;
#endif
    PANIC("");
}

static struct trace_entry *
__find_next_entry(struct trace_iterator *iter, int *ent_cpu,
          unsigned long *missing_events, u64 *ent_ts)
{
    struct trace_buffer *buffer = iter->array_buffer->buffer;
    struct trace_entry *ent, *next = NULL;
    unsigned long lost_events = 0, next_lost = 0;
    int cpu_file = iter->cpu_file;
    u64 next_ts = 0, ts;
    int next_cpu = -1;
    int next_size = 0;
    int cpu;

    /*
     * If we are in a per_cpu trace file, don't bother by iterating over
     * all cpu and peek directly.
     */
    if (cpu_file > RING_BUFFER_ALL_CPUS) {
        if (ring_buffer_empty_cpu(buffer, cpu_file))
            return NULL;
        ent = peek_next_entry(iter, cpu_file, ent_ts, missing_events);
        if (ent_cpu)
            *ent_cpu = cpu_file;

        return ent;
    }

    for_each_tracing_cpu(cpu) {

        if (ring_buffer_empty_cpu(buffer, cpu))
            continue;

        ent = peek_next_entry(iter, cpu, &ts, &lost_events);

        /*
         * Pick the entry with the smallest timestamp:
         */
        if (ent && (!next || ts < next_ts)) {
            next = ent;
            next_cpu = cpu;
            next_ts = ts;
            next_lost = lost_events;
            next_size = iter->ent_size;
        }
    }

    iter->ent_size = next_size;

    if (ent_cpu)
        *ent_cpu = next_cpu;

    if (ent_ts)
        *ent_ts = next_ts;

    if (missing_events)
        *missing_events = next_lost;

    return next;
}

/* Find the next real entry, without updating the iterator itself */
struct trace_entry *trace_find_next_entry(struct trace_iterator *iter,
                      int *ent_cpu, u64 *ent_ts)
{
    /* __find_next_entry will reset ent_size */
    int ent_size = iter->ent_size;
    struct trace_entry *entry;

    /*
     * If called from ftrace_dump(), then the iter->temp buffer
     * will be the static_temp_buf and not created from kmalloc.
     * If the entry size is greater than the buffer, we can
     * not save it. Just return NULL in that case. This is only
     * used to add markers when two consecutive events' time
     * stamps have a large delta. See trace_print_lat_context()
     */
    if (iter->temp == static_temp_buf &&
        STATIC_TEMP_BUF_SIZE < ent_size)
        return NULL;

    /*
     * The __find_next_entry() may call peek_next_entry(), which may
     * call ring_buffer_peek() that may make the contents of iter->ent
     * undefined. Need to copy iter->ent now.
     */
    if (iter->ent && iter->ent != iter->temp) {
        if ((!iter->temp || iter->temp_size < iter->ent_size) &&
            !WARN_ON_ONCE(iter->temp == static_temp_buf)) {
            void *temp;
            temp = kmalloc(iter->ent_size, GFP_KERNEL);
            if (!temp)
                return NULL;
            kfree(iter->temp);
            iter->temp = temp;
            iter->temp_size = iter->ent_size;
        }
        memcpy(iter->temp, iter->ent, iter->ent_size);
        iter->ent = iter->temp;
    }
    entry = __find_next_entry(iter, ent_cpu, NULL, ent_ts);
    /* Put back the original ent_size */
    iter->ent_size = ent_size;

    return entry;
}

/* Find the next real entry, and increment the iterator to the next entry */
void *trace_find_next_entry_inc(struct trace_iterator *iter)
{
    iter->ent = __find_next_entry(iter, &iter->cpu,
                      &iter->lost_events, &iter->ts);

    if (iter->ent)
        trace_iterator_increment(iter);

    return iter->ent ? iter : NULL;
}

static void trace_consume(struct trace_iterator *iter)
{
    ring_buffer_consume(iter->array_buffer->buffer, iter->cpu, &iter->ts,
                &iter->lost_events);
}

void
trace_printk_seq(struct trace_seq *s)
{
    /* Probably should print a warning here. */
    if (s->seq.len >= TRACE_MAX_PRINT)
        s->seq.len = TRACE_MAX_PRINT;

    /*
     * More paranoid code. Although the buffer size is set to
     * PAGE_SIZE, and TRACE_MAX_PRINT is 1000, this is just
     * an extra layer of protection.
     */
    if (WARN_ON_ONCE(s->seq.len >= s->seq.size))
        s->seq.len = s->seq.size - 1;

    /* should be zero ended, but we are paranoid. */
    s->buffer[s->seq.len] = 0;

    printk(KERN_TRACE "%s", s->buffer);

    trace_seq_init(s);
}

static void ftrace_dump_one(struct trace_array *tr, enum ftrace_dump_mode dump_mode)
{
    /* use static because iter can be a bit big for the stack */
    static struct trace_iterator iter;
    unsigned int old_userobj;
    unsigned long flags;
    int cnt = 0, cpu;

    /*
     * Always turn off tracing when we dump.
     * We don't need to show trace output of what happens
     * between multiple crashes.
     *
     * If the user does a sysrq-z, then they can re-enable
     * tracing with echo 1 > tracing_on.
     */
    tracer_tracing_off(tr);

    local_irq_save(flags);

    /* Simulate the iterator */
    trace_init_iter(&iter, tr);

    for_each_tracing_cpu(cpu) {
        atomic_inc(&per_cpu_ptr(iter.array_buffer->data, cpu)->disabled);
    }

    old_userobj = tr->trace_flags & TRACE_ITER_SYM_USEROBJ;

    /* don't look at user memory in panic mode */
    tr->trace_flags &= ~TRACE_ITER_SYM_USEROBJ;

    if (dump_mode == DUMP_ORIG)
        iter.cpu_file = raw_smp_processor_id();
    else
        iter.cpu_file = RING_BUFFER_ALL_CPUS;

    if (tr == &global_trace)
        printk(KERN_TRACE "Dumping ftrace buffer:\n");
    else
        printk(KERN_TRACE "Dumping ftrace instance %s buffer:\n", tr->name);

    /* Did function tracer already get disabled? */
    if (ftrace_is_dead()) {
        printk("# WARNING: FUNCTION TRACING IS CORRUPTED\n");
        printk("#          MAY BE MISSING FUNCTION EVENTS\n");
    }

    /*
     * We need to stop all tracing on all CPUS to read
     * the next buffer. This is a bit expensive, but is
     * not done often. We fill all what we can read,
     * and then release the locks again.
     */

    while (!trace_empty(&iter)) {

        if (!cnt)
            printk(KERN_TRACE "---------------------------------\n");

        cnt++;

        trace_iterator_reset(&iter);
        iter.iter_flags |= TRACE_FILE_LAT_FMT;

        if (trace_find_next_entry_inc(&iter) != NULL) {
            int ret;

            ret = print_trace_line(&iter);
            if (ret != TRACE_TYPE_NO_CONSUME)
                trace_consume(&iter);
        }
        touch_nmi_watchdog();

        trace_printk_seq(&iter.seq);
    }

    if (!cnt)
        printk(KERN_TRACE "   (ftrace buffer empty)\n");
    else
        printk(KERN_TRACE "---------------------------------\n");

    tr->trace_flags |= old_userobj;

    for_each_tracing_cpu(cpu) {
        atomic_dec(&per_cpu_ptr(iter.array_buffer->data, cpu)->disabled);
    }
    local_irq_restore(flags);
}

static void ftrace_dump_by_param(void)
{
    PANIC("");
}

void ftrace_dump(enum ftrace_dump_mode oops_dump_mode)
{
    static atomic_t dump_running;

    /* Only allow one dump user at a time. */
    if (atomic_inc_return(&dump_running) != 1) {
        atomic_dec(&dump_running);
        return;
    }

    switch (oops_dump_mode) {
    case DUMP_ALL:
        ftrace_dump_one(&global_trace, DUMP_ALL);
        break;
    case DUMP_ORIG:
        ftrace_dump_one(&global_trace, DUMP_ORIG);
        break;
    case DUMP_PARAM:
        ftrace_dump_by_param();
        break;
    case DUMP_NONE:
        break;
    default:
        printk(KERN_TRACE "Bad dumping mode, switching to all CPUs dump\n");
        ftrace_dump_one(&global_trace, DUMP_ALL);
    }

    atomic_dec(&dump_running);
}

int trace_empty(struct trace_iterator *iter)
{
    struct ring_buffer_iter *buf_iter;
    int cpu;

    /* If we are looking at one CPU buffer, only check that one */
    if (iter->cpu_file != RING_BUFFER_ALL_CPUS) {
        cpu = iter->cpu_file;
        buf_iter = trace_buffer_iter(iter, cpu);
        if (buf_iter) {
            if (!ring_buffer_iter_empty(buf_iter))
                return 0;
        } else {
            if (!ring_buffer_empty_cpu(iter->array_buffer->buffer, cpu))
                return 0;
        }
        return 1;
    }

    for_each_tracing_cpu(cpu) {
        buf_iter = trace_buffer_iter(iter, cpu);
        if (buf_iter) {
            if (!ring_buffer_iter_empty(buf_iter))
                return 0;
        } else {
            if (!ring_buffer_empty_cpu(iter->array_buffer->buffer, cpu))
                return 0;
        }
    }

    return 1;
}

unsigned long long ns2usecs(u64 nsec)
{
    nsec += 500;
    do_div(nsec, 1000);
    return nsec;
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
