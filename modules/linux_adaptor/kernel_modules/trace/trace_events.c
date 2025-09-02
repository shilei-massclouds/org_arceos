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

LIST_HEAD(ftrace_events);

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

    printk("%s: name(%s)\n", __func__, name);
    if (call->class->raw_init) {
        ret = call->class->raw_init(call);
        if (ret < 0 && ret != -ENOSYS)
            pr_warn("Could not initialize trace events/%s\n", name);
    }

    return ret;
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

#if 0
    register_trigger_cmds();

    /*
     * We need the top trace array to have a working set of trace
     * points at early init, before the debug files and directories
     * are created. Create the file entries now, and attach them
     * to the actual file dentries later.
     */
    __trace_early_add_events(tr);

    early_enable_events(tr, bootup_event_buf, false);

    trace_printk_start_comm();

    register_event_cmds();
#endif
    pr_warn("%s: Enable trace event here!", __func__);

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

int trace_event_raw_init(struct trace_event_call *call)
{
    int id;

    id = register_trace_event(&call->event);
    if (!id)
        return -ENODEV;

    test_event_printk(call);

    return 0;
}


void __init trace_event_init(void)
{
    //event_trace_memsetup();
    init_ftrace_syscalls();
    event_trace_enable();
    //event_trace_init_fields();
}
