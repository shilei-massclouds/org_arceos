#include <linux/spinlock.h>
#include <linux/irq_work.h>
#include <linux/slab.h>
#include "trace.h"
#include "../adaptor.h"

/**
 * trace_pid_list_next - return the next pid in the list
 * @pid_list: The pid list to examine.
 * @pid: The pid to start from
 * @next: The pointer to place the pid that is set starting from @pid.
 *
 * Looks for the next consecutive pid that is in @pid_list starting
 * at the pid specified by @pid. If one is set (including @pid), then
 * that pid is placed into @next.
 *
 * Return 0 when a pid is found, -1 if there are no more pids included.
 */
int trace_pid_list_next(struct trace_pid_list *pid_list, unsigned int pid,
            unsigned int *next)
{
    union upper_chunk *upper_chunk;
    union lower_chunk *lower_chunk;
    unsigned long flags;
    unsigned int upper1;
    unsigned int upper2;
    unsigned int lower;

    if (!pid_list)
        return -ENODEV;

    PANIC("");
}

/**
 * trace_pid_list_first - return the first pid in the list
 * @pid_list: The pid list to examine.
 * @pid: The pointer to place the pid first found pid that is set.
 *
 * Looks for the first pid that is set in @pid_list, and places it
 * into @pid if found.
 *
 * Return 0 when a pid is found, -1 if there are no pids set.
 */
int trace_pid_list_first(struct trace_pid_list *pid_list, unsigned int *pid)
{
    return trace_pid_list_next(pid_list, 0, pid);
}
