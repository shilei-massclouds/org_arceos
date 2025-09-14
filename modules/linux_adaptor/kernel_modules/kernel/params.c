#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/overflow.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../adaptor.h"

/* Protects all built-in parameters, modules use their own param_lock */
static DEFINE_MUTEX(param_lock);

/* Use the module's mutex, or if built-in use the built-in mutex */
#ifdef CONFIG_MODULES
#define KPARAM_MUTEX(mod)   ((mod) ? &(mod)->param_lock : &param_lock)
#else
#define KPARAM_MUTEX(mod)   (&param_lock)
#endif

void kernel_param_lock(struct module *mod)
{
    mutex_lock(KPARAM_MUTEX(mod));
}

void kernel_param_unlock(struct module *mod)
{
    mutex_unlock(KPARAM_MUTEX(mod));
}

static char dash2underscore(char c)
{
    if (c == '-')
        return '_';
    return c;
}

bool parameqn(const char *a, const char *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (dash2underscore(a[i]) != dash2underscore(b[i]))
            return false;
    }
    return true;
}

bool parameq(const char *a, const char *b)
{
    return parameqn(a, b, strlen(a)+1);
}

static bool param_check_unsafe(const struct kernel_param *kp)
{
#if 0
    if (kp->flags & KERNEL_PARAM_FL_HWPARAM &&
        security_locked_down(LOCKDOWN_MODULE_PARAMETERS))
        return false;

    if (kp->flags & KERNEL_PARAM_FL_UNSAFE) {
        pr_notice("Setting dangerous option %s - tainting kernel\n",
              kp->name);
        add_taint(TAINT_USER, LOCKDEP_STILL_OK);
    }
#endif
    pr_notice("%s: No impl.", __func__);

    return true;
}

static int parse_one(char *param,
             char *val,
             const char *doing,
             const struct kernel_param *params,
             unsigned num_params,
             s16 min_level,
             s16 max_level,
             void *arg, parse_unknown_fn handle_unknown)
{
    unsigned int i;
    int err;

    /* Find parameter */
    for (i = 0; i < num_params; i++) {
        if (parameq(param, params[i].name)) {
            if (params[i].level < min_level
                || params[i].level > max_level)
                return 0;
            /* No one handled NULL, so do it here. */
            if (!val &&
                !(params[i].ops->flags & KERNEL_PARAM_OPS_FL_NOARG))
                return -EINVAL;
            pr_debug("handling %s with %p\n", param,
                params[i].ops->set);
            kernel_param_lock(params[i].mod);
            if (param_check_unsafe(&params[i]))
                err = params[i].ops->set(val, &params[i]);
            else
                err = -EPERM;
            kernel_param_unlock(params[i].mod);
            return err;
        }
    }

    if (handle_unknown) {
        pr_debug("doing %s: %s='%s'\n", doing, param, val);
        return handle_unknown(param, val, doing, arg);
    }

    pr_debug("Unknown argument '%s'\n", param);
    PANIC("");
    return -ENOENT;
}

/* Args looks like "foo=bar,bar2 baz=fuz wiz". */
char *parse_args(const char *doing,
         char *args,
         const struct kernel_param *params,
         unsigned num,
         s16 min_level,
         s16 max_level,
         void *arg, parse_unknown_fn unknown)
{
    char *param, *val, *err = NULL;

    /* Chew leading spaces */
    args = skip_spaces(args);

    if (*args)
        pr_debug("doing %s, parsing ARGS: '%s'\n", doing, args);

    while (*args) {
        int ret;
        int irq_was_disabled;

        args = next_arg(args, &param, &val);
        /* Stop at -- */
        if (!val && strcmp(param, "--") == 0)
            return err ?: args;
        irq_was_disabled = irqs_disabled();
        ret = parse_one(param, val, doing, params, num,
                min_level, max_level, arg, unknown);
        if (irq_was_disabled && !irqs_disabled())
            pr_warn("%s: option '%s' enabled irq's!\n",
                doing, param);

        switch (ret) {
        case 0:
            continue;
        case -ENOENT:
            pr_err("%s: Unknown parameter `%s'\n", doing, param);
            break;
        case -ENOSPC:
            pr_err("%s: `%s' too large for parameter `%s'\n",
                   doing, val ?: "", param);
            break;
        default:
            pr_err("%s: `%s' invalid for parameter `%s'\n",
                   doing, val ?: "", param);
            break;
        }

        err = ERR_PTR(ret);
    }

    return err;
}
