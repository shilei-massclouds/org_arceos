#include <linux/syscore_ops.h>
#include <linux/mutex.h>

static LIST_HEAD(syscore_ops_list);
static DEFINE_MUTEX(syscore_ops_lock);

/**
 * register_syscore_ops - Register a set of system core operations.
 * @ops: System core operations to register.
 */
void register_syscore_ops(struct syscore_ops *ops)
{
    mutex_lock(&syscore_ops_lock);
    list_add_tail(&ops->node, &syscore_ops_list);
    mutex_unlock(&syscore_ops_lock);
}
