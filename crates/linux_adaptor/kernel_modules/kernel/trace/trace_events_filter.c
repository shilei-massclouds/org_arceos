#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/mutex.h>
#include <linux/perf_event.h>
#include <linux/slab.h>

#include "trace.h"
#include "trace_output.h"

int filter_assign_type(const char *type)
{
    if (strstr(type, "__data_loc")) {
        if (strstr(type, "char"))
            return FILTER_DYN_STRING;
        if (strstr(type, "cpumask_t"))
            return FILTER_CPUMASK;
    }

    if (strstr(type, "__rel_loc") && strstr(type, "char"))
        return FILTER_RDYN_STRING;

    if (strchr(type, '[') && strstr(type, "char"))
        return FILTER_STATIC_STRING;

    if (strcmp(type, "char *") == 0 || strcmp(type, "const char *") == 0)
        return FILTER_PTR_STRING;

    return FILTER_OTHER;
}
