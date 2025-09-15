#include <linux/kdebug.h>
#include <linux/kprobes.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>
#include <linux/reboot.h>

#define CREATE_TRACE_POINTS
#include <trace/events/notifier.h>

#include "../adaptor.h"

/**
 * notifier_call_chain - Informs the registered notifiers about an event.
 *  @nl:        Pointer to head of the blocking notifier chain
 *  @val:       Value passed unmodified to notifier function
 *  @v:     Pointer passed unmodified to notifier function
 *  @nr_to_call:    Number of notifier functions to be called. Don't care
 *          value of this parameter is -1.
 *  @nr_calls:  Records the number of notifications sent. Don't care
 *          value of this field is NULL.
 *  Return:     notifier_call_chain returns the value returned by the
 *          last notifier function called.
 */
static int notifier_call_chain(struct notifier_block **nl,
                   unsigned long val, void *v,
                   int nr_to_call, int *nr_calls)
{
    int ret = NOTIFY_DONE;
    struct notifier_block *nb, *next_nb;

    nb = rcu_dereference_raw(*nl);

    while (nb && nr_to_call) {
        next_nb = rcu_dereference_raw(nb->next);

#ifdef CONFIG_DEBUG_NOTIFIERS
        if (unlikely(!func_ptr_is_kernel_text(nb->notifier_call))) {
            WARN(1, "Invalid notifier called!");
            nb = next_nb;
            continue;
        }
#endif
        trace_notifier_run((void *)nb->notifier_call);
        ret = nb->notifier_call(nb, val, v);

        if (nr_calls)
            (*nr_calls)++;

        if (ret & NOTIFY_STOP_MASK)
            break;
        nb = next_nb;
        nr_to_call--;
    }
    return ret;
}

/**
 *  atomic_notifier_call_chain - Call functions in an atomic notifier chain
 *  @nh: Pointer to head of the atomic notifier chain
 *  @val: Value passed unmodified to notifier function
 *  @v: Pointer passed unmodified to notifier function
 *
 *  Calls each function in a notifier chain in turn.  The functions
 *  run in an atomic context, so they must not block.
 *  This routine uses RCU to synchronize with changes to the chain.
 *
 *  If the return value of the notifier can be and'ed
 *  with %NOTIFY_STOP_MASK then atomic_notifier_call_chain()
 *  will return immediately, with the return value of
 *  the notifier function which halted execution.
 *  Otherwise the return value is the return value
 *  of the last notifier function called.
 */
int atomic_notifier_call_chain(struct atomic_notifier_head *nh,
                   unsigned long val, void *v)
{
    int ret;

    rcu_read_lock();
    ret = notifier_call_chain(&nh->head, val, v, -1, NULL);
    rcu_read_unlock();

    return ret;
}

/**
 *  atomic_notifier_chain_unregister - Remove notifier from an atomic notifier chain
 *  @nh: Pointer to head of the atomic notifier chain
 *  @n: Entry to remove from notifier chain
 *
 *  Removes a notifier from an atomic notifier chain.
 *
 *  Returns zero on success or %-ENOENT on failure.
 */
int atomic_notifier_chain_unregister(struct atomic_notifier_head *nh,
        struct notifier_block *n)
{
    PANIC("");
}
