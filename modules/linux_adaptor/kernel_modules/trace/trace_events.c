#define pr_fmt(fmt) fmt

#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/tracefs.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/sort.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include <trace/events/sched.h>
#include <trace/syscall.h>

#include <asm/setup.h>

#include "trace_output.h"
#include "../adaptor.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM "TRACE_SYSTEM"

DEFINE_MUTEX(event_mutex);

LIST_HEAD(ftrace_events);

#define GFP_TRACE (GFP_KERNEL | __GFP_ZERO)

static struct kmem_cache *field_cachep;
static struct kmem_cache *file_cachep;

#define MAX_BOOT_TRIGGERS 32

static struct boot_triggers {
    const char      *event;
    char            *trigger;
} bootup_triggers[MAX_BOOT_TRIGGERS];

static int nr_boot_triggers;

#define for_each_event(event, start, end)           \
    for (event = start;                 \
         (unsigned long)event < (unsigned long)end;     \
         event++)

extern struct trace_event_call *__start_ftrace_events[];
extern struct trace_event_call *__stop_ftrace_events[];

static int event_init(struct trace_event_call *call)
{
    int ret = 0;
    const char *name;

    name = trace_event_name(call);
    if (WARN_ON(!name))
        return -EINVAL;

    pr_debug("%s: name(%s)", __func__, name);
    if (call->class->raw_init) {
        ret = call->class->raw_init(call);
        if (ret < 0 && ret != -ENOSYS)
            pr_warn("Could not initialize trace events/%s\n", name);
    }

    return ret;
}

static bool event_in_systems(struct trace_event_call *call,
                 const char *systems)
{
    const char *system;
    const char *p;

    if (!systems)
        return true;

    system = call->class->system;
    p = strstr(systems, system);
    if (!p)
        return false;

    if (p != systems && !isspace(*(p - 1)) && *(p - 1) != ',')
        return false;

    p += strlen(system);
    return !*p || isspace(*p) || *p == ',';
}

static struct trace_event_file *
trace_create_new_event(struct trace_event_call *call,
               struct trace_array *tr)
{
    struct trace_pid_list *no_pid_list;
    struct trace_pid_list *pid_list;
    struct trace_event_file *file;
    unsigned int first;

    if (!event_in_systems(call, tr->system_names))
        return NULL;

    file = kmem_cache_alloc(file_cachep, GFP_TRACE);
    if (!file)
        return ERR_PTR(-ENOMEM);

    pid_list = rcu_dereference_protected(tr->filtered_pids,
                         lockdep_is_held(&event_mutex));
    no_pid_list = rcu_dereference_protected(tr->filtered_no_pids,
                         lockdep_is_held(&event_mutex));

    if (!trace_pid_list_first(pid_list, &first) ||
        !trace_pid_list_first(no_pid_list, &first))
        file->flags |= EVENT_FILE_FL_PID_FILTER;

    file->event_call = call;
    file->tr = tr;
    atomic_set(&file->sm_ref, 0);
    atomic_set(&file->tm_ref, 0);
    INIT_LIST_HEAD(&file->triggers);
    list_add(&file->list, &tr->events);
    refcount_set(&file->ref, 1);

    return file;
}

static int __trace_define_field(struct list_head *head, const char *type,
                const char *name, int offset, int size,
                int is_signed, int filter_type, int len,
                int need_test)
{
    struct ftrace_event_field *field;

    field = kmem_cache_alloc(field_cachep, GFP_TRACE);
    if (!field)
        return -ENOMEM;

    field->name = name;
    field->type = type;

    if (filter_type == FILTER_OTHER)
        field->filter_type = filter_assign_type(type);
    else
        field->filter_type = filter_type;

    field->offset = offset;
    field->size = size;
    field->is_signed = is_signed;
    field->needs_test = need_test;
    field->len = len;

    list_add(&field->link, head);

    return 0;
}

static int trace_define_field_ext(struct trace_event_call *call, const char *type,
               const char *name, int offset, int size, int is_signed,
               int filter_type, int len, int need_test)
{
    struct list_head *head;

    if (WARN_ON(!call->class))
        return 0;

    head = trace_get_fields(call);
    return __trace_define_field(head, type, name, offset, size,
                    is_signed, filter_type, len, need_test);
}

static int
event_define_fields(struct trace_event_call *call)
{
    struct list_head *head;
    int ret = 0;

    /*
     * Other events may have the same class. Only update
     * the fields if they are not already defined.
     */
    head = trace_get_fields(call);
    if (list_empty(head)) {
        struct trace_event_fields *field = call->class->fields_array;
        unsigned int offset = sizeof(struct trace_entry);

        for (; field->type; field++) {
            if (field->type == TRACE_FUNCTION_TYPE) {
                field->define_fields(call);
                break;
            }

            offset = ALIGN(offset, field->align);
            ret = trace_define_field_ext(call, field->type, field->name,
                         offset, field->size,
                         field->is_signed, field->filter_type,
                         field->len, field->needs_test);
            if (WARN_ON_ONCE(ret)) {
                pr_err("error code is %d\n", ret);
                break;
            }

            offset += field->size;
        }
    }

    return ret;
}

static void trace_early_triggers(struct trace_event_file *file, const char *name)
{
    int ret;
    int i;

    for (i = 0; i < nr_boot_triggers; i++) {
        if (strcmp(name, bootup_triggers[i].event))
            continue;
        mutex_lock(&event_mutex);
        ret = trigger_process_regex(file, bootup_triggers[i].trigger);
        mutex_unlock(&event_mutex);
        if (ret)
            pr_err("Failed to register trigger '%s' on event %s\n",
                   bootup_triggers[i].trigger,
                   bootup_triggers[i].event);
    }
}

/*
 * Just create a descriptor for early init. A descriptor is required
 * for enabling events at boot. We want to enable events before
 * the filesystem is initialized.
 */
static int
__trace_early_add_new_event(struct trace_event_call *call,
                struct trace_array *tr)
{
    struct trace_event_file *file;
    int ret;

    file = trace_create_new_event(call, tr);
    /*
     * trace_create_new_event() returns ERR_PTR(-ENOMEM) if failed
     * allocation, or NULL if the event is not part of the tr->system_names.
     * When the event is not part of the tr->system_names, return zero, not
     * an error.
     */
    if (!file)
        return 0;

    if (IS_ERR(file))
        return PTR_ERR(file);

    ret = event_define_fields(call);
    if (ret)
        return ret;

    trace_early_triggers(file, trace_event_name(call));

    return 0;
}

/*
 * For early boot up, the top trace array and the trace arrays created
 * by boot-time tracing require to have a list of events that can be
 * enabled. This must be done before the filesystem is set up in order
 * to allow events to be traced early.
 */
void __trace_early_add_events(struct trace_array *tr)
{
    struct trace_event_call *call;
    int ret;

    list_for_each_entry(call, &ftrace_events, list) {
        /* Early boot up should not have any modules loaded */
        if (!(call->flags & TRACE_EVENT_FL_DYNAMIC) &&
            WARN_ON_ONCE(call->module))
            continue;

        ret = __trace_early_add_new_event(call, tr);
        if (ret < 0)
            pr_warn("Could not create early event %s\n",
                trace_event_name(call));
    }
}

static __init int event_trace_enable(void)
{
    struct trace_array *tr = top_trace_array();
    struct trace_event_call **iter, *call;
    int ret;

    if (!tr)
        return -ENODEV;

    for_each_event(iter, __start_ftrace_events, __stop_ftrace_events) {

        call = *iter;
        ret = event_init(call);
        if (!ret)
            list_add(&call->list, &ftrace_events);
    }

    //register_trigger_cmds();

    /*
     * We need the top trace array to have a working set of trace
     * points at early init, before the debug files and directories
     * are created. Create the file entries now, and attach them
     * to the actual file dentries later.
     */
    __trace_early_add_events(tr);

#if 0
    early_enable_events(tr, bootup_event_buf, false);

    trace_printk_start_comm();

    register_event_cmds();
#endif
    pr_warn("%s: Enable trace event here! [", __func__);
    {
        //char filter[] = "ext4_writepages";
        char filter[] = "mm_filemap_get_pages";
        early_enable_events(tr, filter, false);
    }
    pr_warn("] %s: Enable trace event here!", __func__);

    return 0;
}

static struct trace_event_fields *find_event_field(const char *fmt,
                           struct trace_event_call *call)
{
    struct trace_event_fields *field = call->class->fields_array;
    const char *p = fmt;
    int len;

    if (!(len = str_has_prefix(fmt, "REC->")))
        return NULL;
    fmt += len;
    for (p = fmt; *p; p++) {
        if (!isalnum(*p) && *p != '_')
            break;
    }
    len = p - fmt;

    for (; field->type; field++) {
        if (strncmp(field->name, fmt, len) || field->name[len])
            continue;

        return field;
    }
    return NULL;
}

/*
 * Check if the referenced field is an array and return true,
 * as arrays are OK to dereference.
 */
static bool test_field(const char *fmt, struct trace_event_call *call)
{
    struct trace_event_fields *field;

    field = find_event_field(fmt, call);
    if (!field)
        return false;

    /* This is an array and is OK to dereference. */
    return strchr(field->type, '[') != NULL;
}

/* Look for a string within an argument */
static bool find_print_string(const char *arg, const char *str, const char *end)
{
    const char *r;

    r = strstr(arg, str);
    return r && r < end;
}

/* Return true if the argument pointer is safe */
static bool process_pointer(const char *fmt, int len, struct trace_event_call *call)
{
    const char *r, *e, *a;

    e = fmt + len;

    /* Find the REC-> in the argument */
    r = strstr(fmt, "REC->");
    if (r && r < e) {
        /*
         * Addresses of events on the buffer, or an array on the buffer is
         * OK to dereference. There's ways to fool this, but
         * this is to catch common mistakes, not malicious code.
         */
        a = strchr(fmt, '&');
        if ((a && (a < r)) || test_field(r, call))
            return true;
    } else if (find_print_string(fmt, "__get_dynamic_array(", e)) {
        return true;
    } else if (find_print_string(fmt, "__get_rel_dynamic_array(", e)) {
        return true;
    } else if (find_print_string(fmt, "__get_dynamic_array_len(", e)) {
        return true;
    } else if (find_print_string(fmt, "__get_rel_dynamic_array_len(", e)) {
        return true;
    } else if (find_print_string(fmt, "__get_sockaddr(", e)) {
        return true;
    } else if (find_print_string(fmt, "__get_rel_sockaddr(", e)) {
        return true;
    }
    return false;
}

/* Return true if the string is safe */
static bool process_string(const char *fmt, int len, struct trace_event_call *call)
{
    struct trace_event_fields *field;
    const char *r, *e, *s;

    e = fmt + len;

    /*
     * There are several helper functions that return strings.
     * If the argument contains a function, then assume its field is valid.
     * It is considered that the argument has a function if it has:
     *   alphanumeric or '_' before a parenthesis.
     */
    s = fmt;
    do {
        r = strstr(s, "(");
        if (!r || r >= e)
            break;
        for (int i = 1; r - i >= s; i++) {
            char ch = *(r - i);
            if (isspace(ch))
                continue;
            if (isalnum(ch) || ch == '_')
                return true;
            /* Anything else, this isn't a function */
            break;
        }
        /* A function could be wrapped in parethesis, try the next one */
        s = r + 1;
    } while (s < e);

    /*
     * Check for arrays. If the argument has: foo[REC->val]
     * then it is very likely that foo is an array of strings
     * that are safe to use.
     */
    r = strstr(s, "[");
    if (r && r < e) {
        r = strstr(r, "REC->");
        if (r && r < e)
            return true;
    }

    /*
     * If there's any strings in the argument consider this arg OK as it
     * could be: REC->field ? "foo" : "bar" and we don't want to get into
     * verifying that logic here.
     */
    if (find_print_string(fmt, "\"", e))
        return true;

    /* Dereferenced strings are also valid like any other pointer */
    if (process_pointer(fmt, len, call))
        return true;

    /* Make sure the field is found */
    field = find_event_field(fmt, call);
    if (!field)
        return false;

    /* Test this field's string before printing the event */
    call->flags |= TRACE_EVENT_FL_TEST_STR;
    field->needs_test = 1;

    return true;
}

/*
 * Examine the print fmt of the event looking for unsafe dereference
 * pointers using %p* that could be recorded in the trace event and
 * much later referenced after the pointer was freed. Dereferencing
 * pointers are OK, if it is dereferenced into the event itself.
 */
static void test_event_printk(struct trace_event_call *call)
{
	u64 dereference_flags = 0;
	u64 string_flags = 0;
	bool first = true;
	const char *fmt;
	int parens = 0;
	char in_quote = 0;
	int start_arg = 0;
	int arg = 0;
	int i, e;

	fmt = call->print_fmt;

	if (!fmt)
		return;

	for (i = 0; fmt[i]; i++) {
		switch (fmt[i]) {
		case '\\':
			i++;
			if (!fmt[i])
				return;
			continue;
		case '"':
		case '\'':
			/*
			 * The print fmt starts with a string that
			 * is processed first to find %p* usage,
			 * then after the first string, the print fmt
			 * contains arguments that are used to check
			 * if the dereferenced %p* usage is safe.
			 */
			if (first) {
				if (fmt[i] == '\'')
					continue;
				if (in_quote) {
					arg = 0;
					first = false;
					/*
					 * If there was no %p* uses
					 * the fmt is OK.
					 */
					if (!dereference_flags)
						return;
				}
			}
			if (in_quote) {
				if (in_quote == fmt[i])
					in_quote = 0;
			} else {
				in_quote = fmt[i];
			}
			continue;
		case '%':
			if (!first || !in_quote)
				continue;
			i++;
			if (!fmt[i])
				return;
			switch (fmt[i]) {
			case '%':
				continue;
			case 'p':
 do_pointer:
				/* Find dereferencing fields */
				switch (fmt[i + 1]) {
				case 'B': case 'R': case 'r':
				case 'b': case 'M': case 'm':
				case 'I': case 'i': case 'E':
				case 'U': case 'V': case 'N':
				case 'a': case 'd': case 'D':
				case 'g': case 't': case 'C':
				case 'O': case 'f':
					if (WARN_ONCE(arg == 63,
						      "Too many args for event: %s",
						      trace_event_name(call)))
						return;
					dereference_flags |= 1ULL << arg;
				}
				break;
			default:
			{
				bool star = false;
				int j;

				/* Increment arg if %*s exists. */
				for (j = 0; fmt[i + j]; j++) {
					if (isdigit(fmt[i + j]) ||
					    fmt[i + j] == '.')
						continue;
					if (fmt[i + j] == '*') {
						star = true;
						/* Handle %*pbl case */
						if (!j && fmt[i + 1] == 'p') {
							arg++;
							i++;
							goto do_pointer;
						}
						continue;
					}
					if ((fmt[i + j] == 's')) {
						if (star)
							arg++;
						if (WARN_ONCE(arg == 63,
							      "Too many args for event: %s",
							      trace_event_name(call)))
							return;
						dereference_flags |= 1ULL << arg;
						string_flags |= 1ULL << arg;
					}
					break;
				}
				break;
			} /* default */

			} /* switch */
			arg++;
			continue;
		case '(':
			if (in_quote)
				continue;
			parens++;
			continue;
		case ')':
			if (in_quote)
				continue;
			parens--;
			if (WARN_ONCE(parens < 0,
				      "Paren mismatch for event: %s\narg='%s'\n%*s",
				      trace_event_name(call),
				      fmt + start_arg,
				      (i - start_arg) + 5, "^"))
				return;
			continue;
		case ',':
			if (in_quote || parens)
				continue;
			e = i;
			i++;
			while (isspace(fmt[i]))
				i++;

			/*
			 * If start_arg is zero, then this is the start of the
			 * first argument. The processing of the argument happens
			 * when the end of the argument is found, as it needs to
			 * handle paranthesis and such.
			 */
			if (!start_arg) {
				start_arg = i;
				/* Balance out the i++ in the for loop */
				i--;
				continue;
			}

			if (dereference_flags & (1ULL << arg)) {
				if (string_flags & (1ULL << arg)) {
					if (process_string(fmt + start_arg, e - start_arg, call))
						dereference_flags &= ~(1ULL << arg);
				} else if (process_pointer(fmt + start_arg, e - start_arg, call))
					dereference_flags &= ~(1ULL << arg);
			}

			start_arg = i;
			arg++;
			/* Balance out the i++ in the for loop */
			i--;
		}
	}

	if (dereference_flags & (1ULL << arg)) {
		if (string_flags & (1ULL << arg)) {
			if (process_string(fmt + start_arg, i - start_arg, call))
				dereference_flags &= ~(1ULL << arg);
		} else if (process_pointer(fmt + start_arg, i - start_arg, call))
			dereference_flags &= ~(1ULL << arg);
	}

	/*
	 * If you triggered the below warning, the trace event reported
	 * uses an unsafe dereference pointer %p*. As the data stored
	 * at the trace event time may no longer exist when the trace
	 * event is printed, dereferencing to the original source is
	 * unsafe. The source of the dereference must be copied into the
	 * event itself, and the dereference must access the copy instead.
	 */
	if (WARN_ON_ONCE(dereference_flags)) {
		arg = 1;
		while (!(dereference_flags & 1)) {
			dereference_flags >>= 1;
			arg++;
		}
		pr_warn("event %s has unsafe dereference of argument %d\n",
			trace_event_name(call), arg);
		pr_warn("print_fmt: %s\n", fmt);
	}
}

__init void
early_enable_events(struct trace_array *tr, char *buf, bool disable_first)
{
    char *token;
    int ret;

    while (true) {
        token = strsep(&buf, ",");

        if (!token)
            break;

        if (*token) {
            /* Restarting syscalls requires that we stop them first */
            if (disable_first)
                ftrace_set_clr_event(tr, token, 0);

            ret = ftrace_set_clr_event(tr, token, 1);
            if (ret)
                pr_warn("Failed to enable trace event: %s\n", token);
        }

        /* Put back the comma to allow this to be called again */
        if (buf)
            *(buf - 1) = ',';
    }
}

static int __ftrace_event_enable_disable(struct trace_event_file *file,
                     int enable, int soft_disable)
{
    struct trace_event_call *call = file->event_call;
    struct trace_array *tr = file->tr;
    int ret = 0;
    int disable;

    switch (enable) {
    case 0:
        PANIC("0");
    case 1:
        /*
         * When soft_disable is set and enable is set, we want to
         * register the tracepoint for the event, but leave the event
         * as is. That means, if the event was already enabled, we do
         * nothing (but set SOFT_MODE). If the event is disabled, we
         * set SOFT_DISABLED before enabling the event tracepoint, so
         * it still seems to be disabled.
         */
        if (!soft_disable)
            clear_bit(EVENT_FILE_FL_SOFT_DISABLED_BIT, &file->flags);
        else {
            if (atomic_inc_return(&file->sm_ref) > 1)
                break;
            set_bit(EVENT_FILE_FL_SOFT_MODE_BIT, &file->flags);
            /* Enable use of trace_buffered_event */
            trace_buffered_event_enable();
        }

        if (!(file->flags & EVENT_FILE_FL_ENABLED)) {
            bool cmd = false, tgid = false;

            /* Keep the event disabled, when going to SOFT_MODE. */
            if (soft_disable)
                set_bit(EVENT_FILE_FL_SOFT_DISABLED_BIT, &file->flags);

            if (tr->trace_flags & TRACE_ITER_RECORD_CMD) {
                cmd = true;
                tracing_start_cmdline_record();
                set_bit(EVENT_FILE_FL_RECORDED_CMD_BIT, &file->flags);
            }

            if (tr->trace_flags & TRACE_ITER_RECORD_TGID) {
                tgid = true;
                tracing_start_tgid_record();
                set_bit(EVENT_FILE_FL_RECORDED_TGID_BIT, &file->flags);
            }

            ret = call->class->reg(call, TRACE_REG_REGISTER, file);
            if (ret) {
                if (cmd)
                    tracing_stop_cmdline_record();
                if (tgid)
                    tracing_stop_tgid_record();
                pr_info("event trace: Could not enable event "
                    "%s\n", trace_event_name(call));
                break;
            }
            set_bit(EVENT_FILE_FL_ENABLED_BIT, &file->flags);

            /* WAS_ENABLED gets set but never cleared. */
            set_bit(EVENT_FILE_FL_WAS_ENABLED_BIT, &file->flags);
        }
        break;
    }

    return ret;
}

static int ftrace_event_enable_disable(struct trace_event_file *file,
                       int enable)
{
    return __ftrace_event_enable_disable(file, enable, 0);
}

/*
 * __ftrace_set_clr_event(NULL, NULL, NULL, set) will set/unset all events.
 */
static int
__ftrace_set_clr_event_nolock(struct trace_array *tr, const char *match,
                  const char *sub, const char *event, int set)
{
    struct trace_event_file *file;
    struct trace_event_call *call;
    const char *name;
    int ret = -EINVAL;
    int eret = 0;

    printk("%s: match(%s) sub(%s) event(%s) set(%d)\n", __func__, match, sub, event, set);
    list_for_each_entry(file, &tr->events, list) {

        call = file->event_call;
        name = trace_event_name(call);

        if (!name || !call->class || !call->class->reg)
            continue;

        if (call->flags & TRACE_EVENT_FL_IGNORE_ENABLE)
            continue;

        if (match &&
            strcmp(match, name) != 0 &&
            strcmp(match, call->class->system) != 0)
            continue;

        if (sub && strcmp(sub, call->class->system) != 0)
            continue;

        if (event && strcmp(event, name) != 0)
            continue;

        ret = ftrace_event_enable_disable(file, set);

        /*
         * Save the first error and return that. Some events
         * may still have been enabled, but let the user
         * know that something went wrong.
         */
        if (ret && !eret)
            eret = ret;

        ret = eret;
    }

    return ret;
}

static int __ftrace_set_clr_event(struct trace_array *tr, const char *match,
                  const char *sub, const char *event, int set)
{
    int ret;

    mutex_lock(&event_mutex);
    ret = __ftrace_set_clr_event_nolock(tr, match, sub, event, set);
    mutex_unlock(&event_mutex);

    return ret;
}

int ftrace_set_clr_event(struct trace_array *tr, char *buf, int set)
{
    char *event = NULL, *sub = NULL, *match;
    int ret;

    if (!tr)
        return -ENOENT;
    /*
     * The buf format can be <subsystem>:<event-name>
     *  *:<event-name> means any event by that name.
     *  :<event-name> is the same.
     *
     *  <subsystem>:* means all events in that subsystem
     *  <subsystem>: means the same.
     *
     *  <name> (no ':') means all events in a subsystem with
     *  the name <name> or any event that matches <name>
     */

    match = strsep(&buf, ":");
    if (buf) {
        sub = match;
        event = buf;
        match = NULL;

        if (!strlen(sub) || strcmp(sub, "*") == 0)
            sub = NULL;
        if (!strlen(event) || strcmp(event, "*") == 0)
            event = NULL;
    }

    ret = __ftrace_set_clr_event(tr, match, sub, event, set);

    /* Put back the colon to allow this to be called again */
    if (buf)
        *(buf - 1) = ':';

    return ret;
}

int trace_event_reg(struct trace_event_call *call,
            enum trace_reg type, void *data)
{
    struct trace_event_file *file = data;

    dump_stack();
    printk("%s: ...\n", __func__);
    WARN_ON(!(call->flags & TRACE_EVENT_FL_TRACEPOINT));
    switch (type) {
    case TRACE_REG_REGISTER:
        return tracepoint_probe_register(call->tp,
                         call->class->probe,
                         file);
    case TRACE_REG_UNREGISTER:
        tracepoint_probe_unregister(call->tp,
                        call->class->probe,
                        file);
        return 0;

#ifdef CONFIG_PERF_EVENTS
    case TRACE_REG_PERF_REGISTER:
        return tracepoint_probe_register(call->tp,
                         call->class->perf_probe,
                         call);
    case TRACE_REG_PERF_UNREGISTER:
        tracepoint_probe_unregister(call->tp,
                        call->class->perf_probe,
                        call);
        return 0;
    case TRACE_REG_PERF_OPEN:
    case TRACE_REG_PERF_CLOSE:
    case TRACE_REG_PERF_ADD:
    case TRACE_REG_PERF_DEL:
        return 0;
#endif
    }
    return 0;
}

bool trace_event_ignore_this_pid(struct trace_event_file *trace_file)
{
    struct trace_array *tr = trace_file->tr;
    struct trace_array_cpu *data;
    struct trace_pid_list *no_pid_list;
    struct trace_pid_list *pid_list;

    pid_list = rcu_dereference_raw(tr->filtered_pids);
    no_pid_list = rcu_dereference_raw(tr->filtered_no_pids);

    if (!pid_list && !no_pid_list)
        return false;

    data = this_cpu_ptr(tr->array_buffer.data);

    return data->ignore_pid;
}

void *trace_event_buffer_reserve(struct trace_event_buffer *fbuffer,
                 struct trace_event_file *trace_file,
                 unsigned long len)
{
    struct trace_event_call *event_call = trace_file->event_call;

    if ((trace_file->flags & EVENT_FILE_FL_PID_FILTER) &&
        trace_event_ignore_this_pid(trace_file))
        return NULL;

    /*
     * If CONFIG_PREEMPTION is enabled, then the tracepoint itself disables
     * preemption (adding one to the preempt_count). Since we are
     * interested in the preempt_count at the time the tracepoint was
     * hit, we need to subtract one to offset the increment.
     */
    fbuffer->trace_ctx = tracing_gen_ctx_dec();
    fbuffer->trace_file = trace_file;

    fbuffer->event =
        trace_event_buffer_lock_reserve(&fbuffer->buffer, trace_file,
                        event_call->event.type, len,
                        fbuffer->trace_ctx);
    if (!fbuffer->event)
        return NULL;

    fbuffer->regs = NULL;
    fbuffer->entry = ring_buffer_event_data(fbuffer->event);
    return fbuffer->entry;
}

int trace_event_raw_init(struct trace_event_call *call)
{
    int id;

    id = register_trace_event(&call->event);
    if (!id)
        return -ENODEV;

    test_event_printk(call);

    return 0;
}

static __init int event_trace_memsetup(void)
{
    field_cachep = KMEM_CACHE(ftrace_event_field, SLAB_PANIC);
    file_cachep = KMEM_CACHE(trace_event_file, SLAB_PANIC);
    return 0;
}

void __init trace_event_init(void)
{
    event_trace_memsetup();
    init_ftrace_syscalls();
    event_trace_enable();
    //event_trace_init_fields();
}
