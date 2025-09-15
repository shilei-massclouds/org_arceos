#define pr_fmt(fmt) "reboot: " fmt

#include <linux/atomic.h>
#include <linux/ctype.h>
#include <linux/export.h>
#include <linux/kexec.h>
#include <linux/kmod.h>
#include <linux/kmsg_dump.h>
#include <linux/reboot.h>
#include <linux/suspend.h>
#include <linux/syscalls.h>
#include <linux/syscore_ops.h>
#include <linux/uaccess.h>

#include "../adaptor.h"

struct sys_off_handler {
    struct notifier_block nb;
    int (*sys_off_cb)(struct sys_off_data *data);
    void *cb_data;
    enum sys_off_mode mode;
    bool blocking;
    void *list;
    struct device *dev;
};

/*
 *  Notifier list for kernel code which wants to be called
 *  to power off system.
 */
static ATOMIC_NOTIFIER_HEAD(power_off_handler_list);

static struct sys_off_handler platform_sys_off_handler;

static int legacy_pm_power_off(struct sys_off_data *data)
{
    if (pm_power_off)
        pm_power_off();

    return NOTIFY_DONE;
}

static void free_sys_off_handler(struct sys_off_handler *handler)
{
    if (handler == &platform_sys_off_handler)
        memset(handler, 0, sizeof(*handler));
    else
        kfree(handler);
}

/**
 *  do_kernel_power_off - Execute kernel power-off handler call chain
 *
 *  Expected to be called as last step of the power-off sequence.
 *
 *  Powers off the system immediately if a power-off handler function has
 *  been registered. Otherwise does nothing.
 */
void do_kernel_power_off(void)
{
    struct sys_off_handler *sys_off = NULL;

    /*
     * Register sys-off handlers for legacy PM callback. This allows
     * legacy PM callbacks temporary co-exist with the new sys-off API.
     *
     * TODO: Remove legacy handlers once all legacy PM users will be
     *       switched to the sys-off based APIs.
     */
    if (pm_power_off)
        sys_off = register_sys_off_handler(SYS_OFF_MODE_POWER_OFF,
                           SYS_OFF_PRIO_DEFAULT,
                           legacy_pm_power_off, NULL);

    atomic_notifier_call_chain(&power_off_handler_list, 0, NULL);

    unregister_sys_off_handler(sys_off);
}

/**
 *  register_sys_off_handler - Register sys-off handler
 *  @mode: Sys-off mode
 *  @priority: Handler priority
 *  @callback: Callback function
 *  @cb_data: Callback argument
 *
 *  Registers system power-off or restart handler that will be invoked
 *  at the step corresponding to the given sys-off mode. Handler's callback
 *  should return NOTIFY_DONE to permit execution of the next handler in
 *  the call chain or NOTIFY_STOP to break the chain (in error case for
 *  example).
 *
 *  Multiple handlers can be registered at the default priority level.
 *
 *  Only one handler can be registered at the non-default priority level,
 *  otherwise ERR_PTR(-EBUSY) is returned.
 *
 *  Returns a new instance of struct sys_off_handler on success, or
 *  an ERR_PTR()-encoded error code otherwise.
 */
struct sys_off_handler *
register_sys_off_handler(enum sys_off_mode mode,
             int priority,
             int (*callback)(struct sys_off_data *data),
             void *cb_data)
{
    PANIC("");
}

/**
 *  unregister_sys_off_handler - Unregister sys-off handler
 *  @handler: Sys-off handler
 *
 *  Unregisters given sys-off handler.
 */
void unregister_sys_off_handler(struct sys_off_handler *handler)
{
    int err;

    if (IS_ERR_OR_NULL(handler))
        return;

    if (handler->blocking)
        err = blocking_notifier_chain_unregister(handler->list,
                             &handler->nb);
    else
        err = atomic_notifier_chain_unregister(handler->list,
                               &handler->nb);

    /* sanity check, shall never happen */
    WARN_ON(err);

    free_sys_off_handler(handler);

    PANIC("");
}
