#include <linux/kthread.h>

#include "../adaptor.h"

/**
 * kthread_stop_put - stop a thread and put its task struct
 * @k: thread created by kthread_create().
 *
 * Stops a thread created by kthread_create() and put its task_struct.
 * Only use when holding an extra task struct reference obtained by
 * calling get_task_struct().
 */
int kthread_stop_put(struct task_struct *k)
{
    PANIC("");
#if 0
    int ret;

    ret = kthread_stop(k);
    put_task_struct(k);
    return ret;
#endif
}
