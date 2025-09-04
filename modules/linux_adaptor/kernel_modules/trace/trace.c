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
