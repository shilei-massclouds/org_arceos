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

#if defined(CONFIG_ARM)
#define DEFAULT_REBOOT_MODE     = REBOOT_HARD
#else
#define DEFAULT_REBOOT_MODE
#endif
enum reboot_mode reboot_mode DEFAULT_REBOOT_MODE;

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
 *  to prepare system for power off.
 */
static BLOCKING_NOTIFIER_HEAD(power_off_prep_handler_list);

/*
 *  Notifier list for kernel code which wants to be called
 *  to prepare system for restart.
 */
static BLOCKING_NOTIFIER_HEAD(restart_prep_handler_list);

/*
 *  Notifier list for kernel code which wants to be called
 *  to power off system.
 */
static ATOMIC_NOTIFIER_HEAD(power_off_handler_list);

/*
 *  Notifier list for kernel code which wants to be called
 *  to restart the system.
 */
static ATOMIC_NOTIFIER_HEAD(restart_handler_list);

static struct sys_off_handler platform_sys_off_handler;

static int sys_off_notify(struct notifier_block *nb,
              unsigned long mode, void *cmd)
{
    struct sys_off_handler *handler;
    struct sys_off_data data = {};

    handler = container_of(nb, struct sys_off_handler, nb);
    data.cb_data = handler->cb_data;
    data.mode = mode;
    data.cmd = cmd;
    data.dev = handler->dev;

    return handler->sys_off_cb(&data);
}

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

static struct sys_off_handler *alloc_sys_off_handler(int priority)
{
    struct sys_off_handler *handler;
    gfp_t flags;

    /*
     * Platforms like m68k can't allocate sys_off handler dynamically
     * at the early boot time because memory allocator isn't available yet.
     */
    if (priority == SYS_OFF_PRIO_PLATFORM) {
        handler = &platform_sys_off_handler;
        if (handler->cb_data)
            return ERR_PTR(-EBUSY);
    } else {
        if (system_state > SYSTEM_RUNNING)
            flags = GFP_ATOMIC;
        else
            flags = GFP_KERNEL;

        handler = kzalloc(sizeof(*handler), flags);
        if (!handler)
            return ERR_PTR(-ENOMEM);
    }

    return handler;
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
    struct sys_off_handler *handler;
    int err;

    handler = alloc_sys_off_handler(priority);
    if (IS_ERR(handler))
        return handler;

    switch (mode) {
    case SYS_OFF_MODE_POWER_OFF_PREPARE:
        handler->list = &power_off_prep_handler_list;
        handler->blocking = true;
        break;

    case SYS_OFF_MODE_POWER_OFF:
        handler->list = &power_off_handler_list;
        break;

    case SYS_OFF_MODE_RESTART_PREPARE:
        handler->list = &restart_prep_handler_list;
        handler->blocking = true;
        break;

    case SYS_OFF_MODE_RESTART:
        handler->list = &restart_handler_list;
        break;

    default:
        free_sys_off_handler(handler);
        return ERR_PTR(-EINVAL);
    }

    handler->nb.notifier_call = sys_off_notify;
    handler->nb.priority = priority;
    handler->sys_off_cb = callback;
    handler->cb_data = cb_data;
    handler->mode = mode;

    if (handler->blocking) {
        if (priority == SYS_OFF_PRIO_DEFAULT)
            err = blocking_notifier_chain_register(handler->list,
                                   &handler->nb);
        else
            err = blocking_notifier_chain_register_unique_prio(handler->list,
                                       &handler->nb);
    } else {
        if (priority == SYS_OFF_PRIO_DEFAULT)
            err = atomic_notifier_chain_register(handler->list,
                                 &handler->nb);
        else
            err = atomic_notifier_chain_register_unique_prio(handler->list,
                                     &handler->nb);
    }

    if (err) {
        free_sys_off_handler(handler);
        return ERR_PTR(err);
    }

    return handler;
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

/**
 *  do_kernel_restart - Execute kernel restart handler call chain
 *
 *  Calls functions registered with register_restart_handler.
 *
 *  Expected to be called from machine_restart as last step of the restart
 *  sequence.
 *
 *  Restarts the system immediately if a restart handler function has been
 *  registered. Otherwise does nothing.
 */
void do_kernel_restart(char *cmd)
{
    atomic_notifier_call_chain(&restart_handler_list, reboot_mode, cmd);
}

static void devm_unregister_sys_off_handler(void *data)
{
    struct sys_off_handler *handler = data;

    unregister_sys_off_handler(handler);
}

/**
 *  devm_register_sys_off_handler - Register sys-off handler
 *  @dev: Device that registers handler
 *  @mode: Sys-off mode
 *  @priority: Handler priority
 *  @callback: Callback function
 *  @cb_data: Callback argument
 *
 *  Registers resource-managed sys-off handler.
 *
 *  Returns zero on success, or error code on failure.
 */
int devm_register_sys_off_handler(struct device *dev,
                  enum sys_off_mode mode,
                  int priority,
                  int (*callback)(struct sys_off_data *data),
                  void *cb_data)
{
    struct sys_off_handler *handler;

    handler = register_sys_off_handler(mode, priority, callback, cb_data);
    if (IS_ERR(handler))
        return PTR_ERR(handler);
    handler->dev = dev;

    return devm_add_action_or_reset(dev, devm_unregister_sys_off_handler,
                    handler);
}

int register_restart_handler(struct notifier_block *nb)
{
    return atomic_notifier_chain_register(&restart_handler_list, nb);
}
