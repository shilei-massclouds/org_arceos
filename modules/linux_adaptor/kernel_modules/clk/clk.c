#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/clk/clk-conf.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/pm_runtime.h>
#include <linux/sched.h>
#include <linux/clkdev.h>

#include "clk.h"
#include "../adaptor.h"

static HLIST_HEAD(clk_root_list);
static HLIST_HEAD(clk_orphan_list);

static DEFINE_SPINLOCK(enable_lock);
static DEFINE_MUTEX(prepare_lock);

static struct task_struct *prepare_owner;
static struct task_struct *enable_owner;

static int prepare_refcnt;
static int enable_refcnt;

/* List of registered clks that use runtime PM */
static HLIST_HEAD(clk_rpm_list);
static DEFINE_MUTEX(clk_rpm_list_lock);

/***    private data structures    ***/

struct clk_parent_map {
	const struct clk_hw	*hw;
	struct clk_core		*core;
	const char		*fw_name;
	const char		*name;
	int			index;
};

struct clk_core {
	const char		*name;
	const struct clk_ops	*ops;
	struct clk_hw		*hw;
	struct module		*owner;
	struct device		*dev;
	struct hlist_node	rpm_node;
	struct device_node	*of_node;
	struct clk_core		*parent;
	struct clk_parent_map	*parents;
	u8			num_parents;
	u8			new_parent_index;
	unsigned long		rate;
	unsigned long		req_rate;
	unsigned long		new_rate;
	struct clk_core		*new_parent;
	struct clk_core		*new_child;
	unsigned long		flags;
	bool			orphan;
	bool			rpm_enabled;
	unsigned int		enable_count;
	unsigned int		prepare_count;
	unsigned int		protect_count;
	unsigned long		min_rate;
	unsigned long		max_rate;
	unsigned long		accuracy;
	int			phase;
	struct clk_duty		duty;
	struct hlist_head	children;
	struct hlist_node	child_node;
	struct hlist_head	clks;
	unsigned int		notifier_count;
#ifdef CONFIG_DEBUG_FS
	struct dentry		*dentry;
	struct hlist_node	debug_node;
#endif
	struct kref		ref;
};

#define CREATE_TRACE_POINTS
#include <trace/events/clk.h>

struct clk {
    struct clk_core *core;
    struct device *dev;
    const char *dev_id;
    const char *con_id;
    unsigned long min_rate;
    unsigned long max_rate;
    unsigned int exclusive_count;
    struct hlist_node clks_node;
};

/***           runtime pm          ***/
static int clk_pm_runtime_get(struct clk_core *core)
{
    if (!core->rpm_enabled)
        return 0;

    return pm_runtime_resume_and_get(core->dev);
}

static void clk_pm_runtime_put(struct clk_core *core)
{
    if (!core->rpm_enabled)
        return;

    pm_runtime_put_sync(core->dev);
}

static struct clk_core *__clk_lookup_subtree(const char *name,
                         struct clk_core *core)
{
    struct clk_core *child;
    struct clk_core *ret;

    if (!strcmp(core->name, name))
        return core;

    hlist_for_each_entry(child, &core->children, child_node) {
        ret = __clk_lookup_subtree(name, child);
        if (ret)
            return ret;
    }

    return NULL;
}

static struct clk_core *clk_core_lookup(const char *name)
{
    struct clk_core *root_clk;
    struct clk_core *ret;

    if (!name)
        return NULL;

    /* search the 'proper' clk tree first */
    hlist_for_each_entry(root_clk, &clk_root_list, child_node) {
        ret = __clk_lookup_subtree(name, root_clk);
        if (ret)
            return ret;
    }

    /* if not found, then search the orphan tree */
    hlist_for_each_entry(root_clk, &clk_orphan_list, child_node) {
        ret = __clk_lookup_subtree(name, root_clk);
        if (ret)
            return ret;
    }

    return NULL;
}

/**
 * struct of_clk_provider - Clock provider registration structure
 * @link: Entry in global list of clock providers
 * @node: Pointer to device tree node of clock provider
 * @get: Get clock callback.  Returns NULL or a struct clk for the
 *       given clock specifier
 * @get_hw: Get clk_hw callback.  Returns NULL, ERR_PTR or a
 *       struct clk_hw for the given clock specifier
 * @data: context pointer to be passed into @get callback
 */
struct of_clk_provider {
    struct list_head link;

    struct device_node *node;
    struct clk *(*get)(struct of_phandle_args *clkspec, void *data);
    struct clk_hw *(*get_hw)(struct of_phandle_args *clkspec, void *data);
    void *data;
};

static LIST_HEAD(of_clk_providers);
static DEFINE_MUTEX(of_clk_mutex);

static int of_parse_clkspec(const struct device_node *np, int index,
                const char *name, struct of_phandle_args *out_args)
{
    int ret = -ENOENT;

    /* Walk up the tree of devices looking for a clock property that matches */
    while (np) {
        /*
         * For named clocks, first look up the name in the
         * "clock-names" property.  If it cannot be found, then index
         * will be an error code and of_parse_phandle_with_args() will
         * return -EINVAL.
         */
        if (name)
            index = of_property_match_string(np, "clock-names", name);
        ret = of_parse_phandle_with_args(np, "clocks", "#clock-cells",
                         index, out_args);
        if (!ret)
            break;
        if (name && index >= 0)
            break;

        /*
         * No matching clock found on this node.  If the parent node
         * has a "clock-ranges" property, then we can try one of its
         * clocks.
         */
        np = np->parent;
        if (np && !of_property_present(np, "clock-ranges"))
            break;
        index = 0;

        PANIC("LOOP");
    }

    return ret;
}

static struct clk_hw *
__of_clk_get_hw_from_provider(struct of_clk_provider *provider,
                  struct of_phandle_args *clkspec)
{
    struct clk *clk;

    if (provider->get_hw)
        return provider->get_hw(clkspec, provider->data);

    clk = provider->get(clkspec, provider->data);
    if (IS_ERR(clk))
        return ERR_CAST(clk);
    return __clk_get_hw(clk);
}

static struct clk_hw *
of_clk_get_hw_from_clkspec(struct of_phandle_args *clkspec)
{
    struct of_clk_provider *provider;
    struct clk_hw *hw = ERR_PTR(-EPROBE_DEFER);

    if (!clkspec)
        return ERR_PTR(-EINVAL);

    /* Check if node in clkspec is in disabled/fail state */
    if (!of_device_is_available(clkspec->np))
        return ERR_PTR(-ENOENT);

    mutex_lock(&of_clk_mutex);
    list_for_each_entry(provider, &of_clk_providers, link) {
        if (provider->node == clkspec->np) {
            hw = __of_clk_get_hw_from_provider(provider, clkspec);
            if (!IS_ERR(hw))
                break;
        }
    }
    mutex_unlock(&of_clk_mutex);

    return hw;
}

struct clk_hw *of_clk_get_hw(struct device_node *np, int index,
                 const char *con_id)
{
    int ret;
    struct clk_hw *hw;
    struct of_phandle_args clkspec;

    ret = of_parse_clkspec(np, index, con_id, &clkspec);
    if (ret)
        return ERR_PTR(ret);

    hw = of_clk_get_hw_from_clkspec(&clkspec);
    of_node_put(clkspec.np);

    return hw;
}

/**
 * alloc_clk - Allocate a clk consumer, but leave it unlinked to the clk_core
 * @core: clk to allocate a consumer for
 * @dev_id: string describing device name
 * @con_id: connection ID string on device
 *
 * Returns: clk consumer left unlinked from the consumer list
 */
static struct clk *alloc_clk(struct clk_core *core, const char *dev_id,
                 const char *con_id)
{
    struct clk *clk;

    clk = kzalloc(sizeof(*clk), GFP_KERNEL);
    if (!clk)
        return ERR_PTR(-ENOMEM);

    clk->core = core;
    clk->dev_id = dev_id;
    clk->con_id = kstrdup_const(con_id, GFP_KERNEL);
    clk->max_rate = ULONG_MAX;

    return clk;
}

/**
 * free_clk - Free a clk consumer
 * @clk: clk consumer to free
 *
 * Note, this assumes the clk has been unlinked from the clk_core consumer
 * list.
 */
static void free_clk(struct clk *clk)
{
    kfree_const(clk->con_id);
    kfree(clk);
}

/***           locking             ***/
static void clk_prepare_lock(void)
{
    if (!mutex_trylock(&prepare_lock)) {
        if (prepare_owner == current) {
            prepare_refcnt++;
            return;
        }
        mutex_lock(&prepare_lock);
    }
    WARN_ON_ONCE(prepare_owner != NULL);
    WARN_ON_ONCE(prepare_refcnt != 0);
    prepare_owner = current;
    prepare_refcnt = 1;
}

static void clk_prepare_unlock(void)
{
    WARN_ON_ONCE(prepare_owner != current);
    WARN_ON_ONCE(prepare_refcnt == 0);

    if (--prepare_refcnt)
        return;
    prepare_owner = NULL;
    mutex_unlock(&prepare_lock);
}

/**
 * clk_core_link_consumer - Add a clk consumer to the list of consumers in a clk_core
 * @core: clk to add consumer to
 * @clk: consumer to link to a clk
 */
static void clk_core_link_consumer(struct clk_core *core, struct clk *clk)
{
    clk_prepare_lock();
    hlist_add_head(&clk->clks_node, &core->clks);
    clk_prepare_unlock();
}

/**
 * clk_hw_create_clk: Allocate and link a clk consumer to a clk_core given
 * a clk_hw
 * @dev: clk consumer device
 * @hw: clk_hw associated with the clk being consumed
 * @dev_id: string describing device name
 * @con_id: connection ID string on device
 *
 * This is the main function used to create a clk pointer for use by clk
 * consumers. It connects a consumer to the clk_core and clk_hw structures
 * used by the framework and clk provider respectively.
 */
struct clk *clk_hw_create_clk(struct device *dev, struct clk_hw *hw,
                  const char *dev_id, const char *con_id)
{
    struct clk *clk;
    struct clk_core *core;

    /* This is to allow this function to be chained to others */
    if (IS_ERR_OR_NULL(hw))
        return ERR_CAST(hw);

    core = hw->core;
    clk = alloc_clk(core, dev_id, con_id);
    if (IS_ERR(clk))
        return clk;
    clk->dev = dev;

    if (!try_module_get(core->owner)) {
        free_clk(clk);
        return ERR_PTR(-ENOENT);
    }

    kref_get(&core->ref);
    clk_core_link_consumer(core, clk);

    return clk;
}

struct clk_hw *__clk_get_hw(struct clk *clk)
{
    return !clk ? NULL : clk->core->hw;
}

const char *clk_hw_get_name(const struct clk_hw *hw)
{
    return hw->core->name;
}

/**
 * of_clk_get_parent_count() - Count the number of clocks a device node has
 * @np: device node to count
 *
 * Returns: The number of clocks that are possible parents of this node
 */
unsigned int of_clk_get_parent_count(const struct device_node *np)
{
    int count;

    count = of_count_phandle_with_args(np, "clocks", "#clock-cells");
    if (count < 0)
        return 0;

    return count;
}

/**
 * clk_hw_unregister - unregister a currently registered clk_hw
 * @hw: hardware-specific clock data to unregister
 */
void clk_hw_unregister(struct clk_hw *hw)
{
    clk_unregister(hw->clk);
}

static void devm_clk_hw_unregister_cb(struct device *dev, void *res)
{
    clk_hw_unregister(*(struct clk_hw **)res);
}

/**
 * devm_clk_hw_register - resource managed clk_hw_register()
 * @dev: device that is registering this clock
 * @hw: link to hardware-specific clock data
 *
 * Managed clk_hw_register(). Clocks registered by this function are
 * automatically clk_hw_unregister()ed on driver detach. See clk_hw_register()
 * for more information.
 */
int devm_clk_hw_register(struct device *dev, struct clk_hw *hw)
{
    struct clk_hw **hwp;
    int ret;

    hwp = devres_alloc(devm_clk_hw_unregister_cb, sizeof(*hwp), GFP_KERNEL);
    if (!hwp)
        return -ENOMEM;

    ret = clk_hw_register(dev, hw);
    if (!ret) {
        *hwp = hw;
        devres_add(dev, hwp);
    } else {
        devres_free(hwp);
    }

    return ret;
}

/**
 * dev_or_parent_of_node() - Get device node of @dev or @dev's parent
 * @dev: Device to get device node of
 *
 * Return: device node pointer of @dev, or the device node pointer of
 * @dev->parent if dev doesn't have a device node, or NULL if neither
 * @dev or @dev->parent have a device node.
 */
static struct device_node *dev_or_parent_of_node(struct device *dev)
{
    struct device_node *np;

    if (!dev)
        return NULL;

    np = dev_of_node(dev);
    if (!np)
        np = dev_of_node(dev->parent);

    return np;
}

/* Free memory allocated for a struct clk_core */
static void __clk_release(struct kref *ref)
{
#if 0
    struct clk_core *core = container_of(ref, struct clk_core, ref);

    if (core->rpm_enabled) {
        mutex_lock(&clk_rpm_list_lock);
        hlist_del(&core->rpm_node);
        mutex_unlock(&clk_rpm_list_lock);
    }

    clk_core_free_parent_map(core);
    kfree_const(core->name);
    kfree(core);
#endif
    PANIC("");
}

static void clk_pm_runtime_init(struct clk_core *core)
{
    struct device *dev = core->dev;

    if (dev && pm_runtime_enabled(dev)) {
        core->rpm_enabled = true;

        mutex_lock(&clk_rpm_list_lock);
        hlist_add_head(&core->rpm_node, &clk_rpm_list);
        mutex_unlock(&clk_rpm_list_lock);
    }
}

static int clk_cpy_name(const char **dst_p, const char *src, bool must_exist)
{
    const char *dst;

    if (!src) {
        if (must_exist)
            return -EINVAL;
        return 0;
    }

    *dst_p = dst = kstrdup_const(src, GFP_KERNEL);
    if (!dst)
        return -ENOMEM;

    return 0;
}

static int clk_core_populate_parent_map(struct clk_core *core,
                    const struct clk_init_data *init)
{
    u8 num_parents = init->num_parents;
    const char * const *parent_names = init->parent_names;
    const struct clk_hw **parent_hws = init->parent_hws;
    const struct clk_parent_data *parent_data = init->parent_data;
    int i, ret = 0;
    struct clk_parent_map *parents, *parent;

    if (!num_parents)
        return 0;
    /*
     * Avoid unnecessary string look-ups of clk_core's possible parents by
     * having a cache of names/clk_hw pointers to clk_core pointers.
     */
    parents = kcalloc(num_parents, sizeof(*parents), GFP_KERNEL);
    core->parents = parents;
    if (!parents)
        return -ENOMEM;

    /* Copy everything over because it might be __initdata */
    for (i = 0, parent = parents; i < num_parents; i++, parent++) {
        parent->index = -1;
        if (parent_names) {
            /* throw a WARN if any entries are NULL */
            WARN(!parent_names[i],
                "%s: invalid NULL in %s's .parent_names\n",
                __func__, core->name);
            ret = clk_cpy_name(&parent->name, parent_names[i],
                       true);
        } else if (parent_data) {
            parent->hw = parent_data[i].hw;
            parent->index = parent_data[i].index;
            ret = clk_cpy_name(&parent->fw_name,
                       parent_data[i].fw_name, false);
            if (!ret)
                ret = clk_cpy_name(&parent->name,
                           parent_data[i].name,
                           false);
        } else if (parent_hws) {
            parent->hw = parent_hws[i];
        } else {
            ret = -EINVAL;
            WARN(1, "Must specify parents if num_parents > 0\n");
        }

        if (ret) {
            do {
                kfree_const(parents[i].name);
                kfree_const(parents[i].fw_name);
            } while (--i >= 0);
            kfree(parents);

            return ret;
        }
    }

    return 0;
}

/**
 * clk_debug_register - add a clk node to the debugfs clk directory
 * @core: the clk being added to the debugfs clk directory
 *
 * Dynamically adds a clk to the debugfs clk directory if debugfs has been
 * initialized.  Otherwise it bails out early since the debugfs clk directory
 * will be created lazily by clk_debug_init as part of a late_initcall.
 */
static void clk_debug_register(struct clk_core *core)
{
    pr_notice("%s: No impl.", __func__);
}

 /**
 * clk_debug_unregister - remove a clk node from the debugfs clk directory
 * @core: the clk being removed from the debugfs clk directory
 *
 * Dynamically removes a clk and all its child nodes from the
 * debugfs clk directory if clk->dentry points to debugfs created by
 * clk_debug_register in __clk_core_init.
 */
static void clk_debug_unregister(struct clk_core *core)
{
    pr_notice("%s: No impl.", __func__);
}

/**
 * clk_core_get - Find the clk_core parent of a clk
 * @core: clk to find parent of
 * @p_index: parent index to search for
 *
 * This is the preferred method for clk providers to find the parent of a
 * clk when that parent is external to the clk controller. The parent_names
 * array is indexed and treated as a local name matching a string in the device
 * node's 'clock-names' property or as the 'con_id' matching the device's
 * dev_name() in a clk_lookup. This allows clk providers to use their own
 * namespace instead of looking for a globally unique parent string.
 *
 * For example the following DT snippet would allow a clock registered by the
 * clock-controller@c001 that has a clk_init_data::parent_data array
 * with 'xtal' in the 'name' member to find the clock provided by the
 * clock-controller@f00abcd without needing to get the globally unique name of
 * the xtal clk.
 *
 *      parent: clock-controller@f00abcd {
 *              reg = <0xf00abcd 0xabcd>;
 *              #clock-cells = <0>;
 *      };
 *
 *      clock-controller@c001 {
 *              reg = <0xc001 0xf00d>;
 *              clocks = <&parent>;
 *              clock-names = "xtal";
 *              #clock-cells = <1>;
 *      };
 *
 * Returns: -ENOENT when the provider can't be found or the clk doesn't
 * exist in the provider or the name can't be found in the DT node or
 * in a clkdev lookup. NULL when the provider knows about the clk but it
 * isn't provided on this system.
 * A valid clk_core pointer when the clk can be found in the provider.
 */
static struct clk_core *clk_core_get(struct clk_core *core, u8 p_index)
{
    const char *name = core->parents[p_index].fw_name;
    int index = core->parents[p_index].index;
    struct clk_hw *hw = ERR_PTR(-ENOENT);
    struct device *dev = core->dev;
    const char *dev_id = dev ? dev_name(dev) : NULL;
    struct device_node *np = core->of_node;
    struct of_phandle_args clkspec;

    if (np && (name || index >= 0) &&
        !of_parse_clkspec(np, index, name, &clkspec)) {
        hw = of_clk_get_hw_from_clkspec(&clkspec);
        of_node_put(clkspec.np);
    } else if (name) {
        /*
         * If the DT search above couldn't find the provider fallback to
         * looking up via clkdev based clk_lookups.
         */
        hw = clk_find_hw(dev_id, name);
    }

    if (IS_ERR(hw))
        return ERR_CAST(hw);

    if (!hw)
        return NULL;

    return hw->core;
}

static void clk_core_fill_parent_index(struct clk_core *core, u8 index)
{
    struct clk_parent_map *entry = &core->parents[index];
    struct clk_core *parent;

    if (entry->hw) {
        parent = entry->hw->core;
    } else {
        parent = clk_core_get(core, index);
        if (PTR_ERR(parent) == -ENOENT && entry->name)
            parent = clk_core_lookup(entry->name);
    }

    /*
     * We have a direct reference but it isn't registered yet?
     * Orphan it and let clk_reparent() update the orphan status
     * when the parent is registered.
     */
    if (!parent)
        parent = ERR_PTR(-EPROBE_DEFER);

    /* Only cache it if it's not an error */
    if (!IS_ERR(parent))
        entry->core = parent;
}

static struct clk_core *clk_core_get_parent_by_index(struct clk_core *core,
                             u8 index)
{
    if (!core || index >= core->num_parents || !core->parents)
        return NULL;

    if (!core->parents[index].core)
        clk_core_fill_parent_index(core, index);

    return core->parents[index].core;
}

static struct clk_core *__clk_init_parent(struct clk_core *core)
{
    u8 index = 0;

    if (core->num_parents > 1 && core->ops->get_parent)
        index = core->ops->get_parent(core->hw);

    return clk_core_get_parent_by_index(core, index);
}

static unsigned long clk_core_get_accuracy_no_lock(struct clk_core *core)
{
    if (!core)
        return 0;

    return core->accuracy;
}

static int clk_core_get_phase(struct clk_core *core)
{
    int ret;

    lockdep_assert_held(&prepare_lock);
    if (!core->ops->get_phase)
        return 0;

    /* Always try to update cached phase if possible */
    ret = core->ops->get_phase(core->hw);
    if (ret >= 0)
        core->phase = ret;

    return ret;
}

static unsigned long clk_core_get_rate_nolock(struct clk_core *core)
{
    if (!core)
        return 0;

    if (!core->num_parents || core->parent)
        return core->rate;

    /*
     * Clk must have a parent because num_parents > 0 but the parent isn't
     * known yet. Best to return 0 as the rate of this clk until we can
     * properly recalc the rate based on the parent's rate.
     */
    return 0;
}

static void clk_core_reset_duty_cycle_nolock(struct clk_core *core)
{
    /* Assume a default value of 50% */
    core->duty.num = 1;
    core->duty.den = 2;
}

static int clk_core_update_duty_cycle_nolock(struct clk_core *core);

static int clk_core_update_duty_cycle_parent_nolock(struct clk_core *core)
{
    int ret = 0;

    if (core->parent &&
        core->flags & CLK_DUTY_CYCLE_PARENT) {
        ret = clk_core_update_duty_cycle_nolock(core->parent);
        memcpy(&core->duty, &core->parent->duty, sizeof(core->duty));
    } else {
        clk_core_reset_duty_cycle_nolock(core);
    }

    return ret;
}

static int clk_core_update_duty_cycle_nolock(struct clk_core *core)
{
    struct clk_duty *duty = &core->duty;
    int ret = 0;

    if (!core->ops->get_duty_cycle)
        return clk_core_update_duty_cycle_parent_nolock(core);

#if 0
    ret = core->ops->get_duty_cycle(core->hw, duty);
    if (ret)
        goto reset;

    /* Don't trust the clock provider too much */
    if (duty->den == 0 || duty->num > duty->den) {
        ret = -EINVAL;
        goto reset;
    }
#endif

    PANIC("");
    return 0;

reset:
    clk_core_reset_duty_cycle_nolock(core);
    return ret;
}

static void clk_core_reparent_orphans_nolock(void)
{
    struct clk_core *orphan;
    struct hlist_node *tmp2;

    /*
     * walk the list of orphan clocks and reparent any that newly finds a
     * parent.
     */
    hlist_for_each_entry_safe(orphan, tmp2, &clk_orphan_list, child_node) {
        struct clk_core *parent = __clk_init_parent(orphan);

        /*
         * We need to use __clk_set_parent_before() and _after() to
         * properly migrate any prepare/enable count of the orphan
         * clock. This is important for CLK_IS_CRITICAL clocks, which
         * are enabled during init but might not have a parent yet.
         */
        if (parent) {
#if 0
            /* update the clk tree topology */
            __clk_set_parent_before(orphan, parent);
            __clk_set_parent_after(orphan, parent, NULL);
            __clk_recalc_accuracies(orphan);
            __clk_recalc_rates(orphan, true, 0);

            /*
             * __clk_init_parent() will set the initial req_rate to
             * 0 if the clock doesn't have clk_ops::recalc_rate and
             * is an orphan when it's registered.
             *
             * 'req_rate' is used by clk_set_rate_range() and
             * clk_put() to trigger a clk_set_rate() call whenever
             * the boundaries are modified. Let's make sure
             * 'req_rate' is set to something non-zero so that
             * clk_set_rate_range() doesn't drop the frequency.
             */
            orphan->req_rate = orphan->rate;
#endif
            PANIC("stage1");
        }
    }
}

/**
 * __clk_core_init - initialize the data structures in a struct clk_core
 * @core:   clk_core being initialized
 *
 * Initializes the lists in struct clk_core, queries the hardware for the
 * parent and rate and sets them both.
 */
static int __clk_core_init(struct clk_core *core)
{
    int ret;
    struct clk_core *parent;
    unsigned long rate;
    int phase;

    clk_prepare_lock();

    /*
     * Set hw->core after grabbing the prepare_lock to synchronize with
     * callers of clk_core_fill_parent_index() where we treat hw->core
     * being NULL as the clk not being registered yet. This is crucial so
     * that clks aren't parented until their parent is fully registered.
     */
    core->hw->core = core;

    ret = clk_pm_runtime_get(core);
    if (ret)
        goto unlock;

    /* check to see if a clock with this name is already registered */
    if (clk_core_lookup(core->name)) {
        pr_debug("%s: clk %s already initialized\n",
                __func__, core->name);
        ret = -EEXIST;
        goto out;
    }
    /* check that clk_ops are sane.  See Documentation/driver-api/clk.rst */
    if (core->ops->set_rate &&
        !((core->ops->round_rate || core->ops->determine_rate) &&
          core->ops->recalc_rate)) {
        pr_err("%s: %s must implement .round_rate or .determine_rate in addition to .recalc_rate\n",
               __func__, core->name);
        ret = -EINVAL;
        goto out;
    }

    if (core->ops->set_parent && !core->ops->get_parent) {
        pr_err("%s: %s must implement .get_parent & .set_parent\n",
               __func__, core->name);
        ret = -EINVAL;
        goto out;
    }

    if (core->ops->set_parent && !core->ops->determine_rate) {
        pr_err("%s: %s must implement .set_parent & .determine_rate\n",
            __func__, core->name);
        ret = -EINVAL;
        goto out;
    }

    if (core->num_parents > 1 && !core->ops->get_parent) {
        pr_err("%s: %s must implement .get_parent as it has multi parents\n",
               __func__, core->name);
        ret = -EINVAL;
        goto out;
    }
    if (core->ops->set_rate_and_parent &&
            !(core->ops->set_parent && core->ops->set_rate)) {
        pr_err("%s: %s must implement .set_parent & .set_rate\n",
                __func__, core->name);
        ret = -EINVAL;
        goto out;
    }

    /*
     * optional platform-specific magic
     *
     * The .init callback is not used by any of the basic clock types, but
     * exists for weird hardware that must perform initialization magic for
     * CCF to get an accurate view of clock for any other callbacks. It may
     * also be used needs to perform dynamic allocations. Such allocation
     * must be freed in the terminate() callback.
     * This callback shall not be used to initialize the parameters state,
     * such as rate, parent, etc ...
     *
     * If it exist, this callback should called before any other callback of
     * the clock
     */
    if (core->ops->init) {
        ret = core->ops->init(core->hw);
        if (ret)
            goto out;
    }

    parent = core->parent = __clk_init_parent(core);

    /*
     * Populate core->parent if parent has already been clk_core_init'd. If
     * parent has not yet been clk_core_init'd then place clk in the orphan
     * list.  If clk doesn't have any parents then place it in the root
     * clk list.
     *
     * Every time a new clk is clk_init'd then we walk the list of orphan
     * clocks and re-parent any that are children of the clock currently
     * being clk_init'd.
     */
    if (parent) {
        hlist_add_head(&core->child_node, &parent->children);
        core->orphan = parent->orphan;
    } else if (!core->num_parents) {
        hlist_add_head(&core->child_node, &clk_root_list);
        core->orphan = false;
    } else {
        hlist_add_head(&core->child_node, &clk_orphan_list);
        core->orphan = true;
    }

    /*
     * Set clk's accuracy.  The preferred method is to use
     * .recalc_accuracy. For simple clocks and lazy developers the default
     * fallback is to use the parent's accuracy.  If a clock doesn't have a
     * parent (or is orphaned) then accuracy is set to zero (perfect
     * clock).
     */
    if (core->ops->recalc_accuracy)
        core->accuracy = core->ops->recalc_accuracy(core->hw,
                    clk_core_get_accuracy_no_lock(parent));
    else if (parent)
        core->accuracy = parent->accuracy;
    else
        core->accuracy = 0;

    /*
     * Set clk's phase by clk_core_get_phase() caching the phase.
     * Since a phase is by definition relative to its parent, just
     * query the current clock phase, or just assume it's in phase.
     */
    phase = clk_core_get_phase(core);
    if (phase < 0) {
        ret = phase;
        pr_warn("%s: Failed to get phase for clk '%s'\n", __func__,
            core->name);
        goto out;
    }

    /*
     * Set clk's duty cycle.
     */
    clk_core_update_duty_cycle_nolock(core);

    /*
     * Set clk's rate.  The preferred method is to use .recalc_rate.  For
     * simple clocks and lazy developers the default fallback is to use the
     * parent's rate.  If a clock doesn't have a parent (or is orphaned)
     * then rate is set to zero.
     */
    if (core->ops->recalc_rate)
        rate = core->ops->recalc_rate(core->hw,
                clk_core_get_rate_nolock(parent));
    else if (parent)
        rate = parent->rate;
    else
        rate = 0;

    core->rate = core->req_rate = rate;

    /*
     * Enable CLK_IS_CRITICAL clocks so newly added critical clocks
     * don't get accidentally disabled when walking the orphan tree and
     * reparenting clocks
     */
    if (core->flags & CLK_IS_CRITICAL) {
#if 0
        ret = clk_core_prepare(core);
        if (ret) {
            pr_warn("%s: critical clk '%s' failed to prepare\n",
                   __func__, core->name);
            goto out;
        }

        ret = clk_core_enable_lock(core);
        if (ret) {
            pr_warn("%s: critical clk '%s' failed to enable\n",
                   __func__, core->name);
            clk_core_unprepare(core);
            goto out;
        }
#endif
        PANIC("CLK_IS_CRITICAL");
    }

    clk_core_reparent_orphans_nolock();
out:
    clk_pm_runtime_put(core);
unlock:
    if (ret) {
        hlist_del_init(&core->child_node);
        core->hw->core = NULL;
    }

    clk_prepare_unlock();

    if (!ret)
        clk_debug_register(core);

    return ret;
}

static struct clk *
__clk_register(struct device *dev, struct device_node *np, struct clk_hw *hw)
{
    int ret;
    struct clk_core *core;
    const struct clk_init_data *init = hw->init;

    /*
     * The init data is not supposed to be used outside of registration path.
     * Set it to NULL so that provider drivers can't use it either and so that
     * we catch use of hw->init early on in the core.
     */
    hw->init = NULL;

    core = kzalloc(sizeof(*core), GFP_KERNEL);
    if (!core) {
        ret = -ENOMEM;
        goto fail_out;
    }

    kref_init(&core->ref);

    core->name = kstrdup_const(init->name, GFP_KERNEL);
    if (!core->name) {
        ret = -ENOMEM;
        goto fail_name;
    }

    if (WARN_ON(!init->ops)) {
        ret = -EINVAL;
        goto fail_ops;
    }
    core->ops = init->ops;

    core->dev = dev;
    clk_pm_runtime_init(core);
    core->of_node = np;
    if (dev && dev->driver)
        core->owner = dev->driver->owner;
    core->hw = hw;
    core->flags = init->flags;
    core->num_parents = init->num_parents;
    core->min_rate = 0;
    core->max_rate = ULONG_MAX;

    ret = clk_core_populate_parent_map(core, init);
    if (ret)
        goto fail_parents;

    INIT_HLIST_HEAD(&core->clks);

    /*
     * Don't call clk_hw_create_clk() here because that would pin the
     * provider module to itself and prevent it from ever being removed.
     */
    hw->clk = alloc_clk(core, NULL, NULL);
    if (IS_ERR(hw->clk)) {
        ret = PTR_ERR(hw->clk);
        goto fail_create_clk;
    }

    clk_core_link_consumer(core, hw->clk);

    ret = __clk_core_init(core);
    if (!ret)
        return hw->clk;

#if 0
    clk_prepare_lock();
    clk_core_unlink_consumer(hw->clk);
    clk_prepare_unlock();

    free_clk(hw->clk);
    hw->clk = NULL;
#endif
    PANIC("");

fail_create_clk:
fail_parents:
fail_ops:
fail_name:
    kref_put(&core->ref, __clk_release);
fail_out:
    PANIC("");
    return ERR_PTR(ret);
}

/**
 * clk_hw_register - register a clk_hw and return an error code
 * @dev: device that is registering this clock
 * @hw: link to hardware-specific clock data
 *
 * clk_hw_register is the primary interface for populating the clock tree with
 * new clock nodes. It returns an integer equal to zero indicating success or
 * less than zero indicating failure. Drivers must test for an error code after
 * calling clk_hw_register().
 */
int clk_hw_register(struct device *dev, struct clk_hw *hw)
{
    return PTR_ERR_OR_ZERO(__clk_register(dev, dev_or_parent_of_node(dev),
                   hw));
}

static void devm_of_clk_release_provider(struct device *dev, void *res)
{
    of_clk_del_provider(*(struct device_node **)res);
}

/*
 * We allow a child device to use its parent device as the clock provider node
 * for cases like MFD sub-devices where the child device driver wants to use
 * devm_*() APIs but not list the device in DT as a sub-node.
 */
static struct device_node *get_clk_provider_node(struct device *dev)
{
    struct device_node *np, *parent_np;

    np = dev->of_node;
    parent_np = dev->parent ? dev->parent->of_node : NULL;

    if (!of_property_present(np, "#clock-cells"))
        if (of_property_present(parent_np, "#clock-cells"))
            np = parent_np;

    return np;
}

/**
 * devm_of_clk_add_hw_provider() - Managed clk provider node registration
 * @dev: Device acting as the clock provider (used for DT node and lifetime)
 * @get: callback for decoding clk_hw
 * @data: context pointer for @get callback
 *
 * Registers clock provider for given device's node. If the device has no DT
 * node or if the device node lacks of clock provider information (#clock-cells)
 * then the parent device's node is scanned for this information. If parent node
 * has the #clock-cells then it is used in registration. Provider is
 * automatically released at device exit.
 *
 * Return: 0 on success or an errno on failure.
 */
int devm_of_clk_add_hw_provider(struct device *dev,
            struct clk_hw *(*get)(struct of_phandle_args *clkspec,
                          void *data),
            void *data)
{
    struct device_node **ptr, *np;
    int ret;

    ptr = devres_alloc(devm_of_clk_release_provider, sizeof(*ptr),
               GFP_KERNEL);
    if (!ptr)
        return -ENOMEM;

    np = get_clk_provider_node(dev);
    ret = of_clk_add_hw_provider(np, get, data);
    if (!ret) {
        *ptr = np;
        devres_add(dev, ptr);
    } else {
        devres_free(ptr);
    }

    return ret;
}

/**
 * of_clk_del_provider() - Remove a previously registered clock provider
 * @np: Device node pointer associated with clock provider
 */
void of_clk_del_provider(struct device_node *np)
{
    struct of_clk_provider *cp;

    if (!np)
        return;

    mutex_lock(&of_clk_mutex);
    list_for_each_entry(cp, &of_clk_providers, link) {
        if (cp->node == np) {
            list_del(&cp->link);
            fwnode_dev_initialized(&np->fwnode, false);
            of_node_put(cp->node);
            kfree(cp);
            break;
        }
    }
    mutex_unlock(&of_clk_mutex);
}

static void clk_core_reparent_orphans(void)
{
    clk_prepare_lock();
    clk_core_reparent_orphans_nolock();
    clk_prepare_unlock();
}

/**
 * of_clk_add_hw_provider() - Register a clock provider for a node
 * @np: Device node pointer associated with clock provider
 * @get: callback for decoding clk_hw
 * @data: context pointer for @get callback.
 */
int of_clk_add_hw_provider(struct device_node *np,
               struct clk_hw *(*get)(struct of_phandle_args *clkspec,
                         void *data),
               void *data)
{
    struct of_clk_provider *cp;
    int ret;

    if (!np)
        return 0;

    cp = kzalloc(sizeof(*cp), GFP_KERNEL);
    if (!cp)
        return -ENOMEM;

    cp->node = of_node_get(np);
    cp->data = data;
    cp->get_hw = get;

    mutex_lock(&of_clk_mutex);
    list_add(&cp->link, &of_clk_providers);
    mutex_unlock(&of_clk_mutex);
    pr_debug("Added clk_hw provider from %pOF\n", np);

    clk_core_reparent_orphans();

    ret = of_clk_set_defaults(np, true);
    if (ret < 0)
        of_clk_del_provider(np);

    fwnode_dev_initialized(&np->fwnode, true);

    return ret;
}

struct clk_hw *
of_clk_hw_onecell_get(struct of_phandle_args *clkspec, void *data)
{
    struct clk_hw_onecell_data *hw_data = data;
    unsigned int idx = clkspec->args[0];

    if (idx >= hw_data->num) {
        pr_err("%s: invalid index %u\n", __func__, idx);
        return ERR_PTR(-EINVAL);
    }

    return hw_data->hws[idx];
}

static void clk_core_unprepare(struct clk_core *core)
{
    PANIC("");
}

static void clk_core_rate_protect(struct clk_core *core)
{
    lockdep_assert_held(&prepare_lock);

    if (!core)
        return;

    if (core->protect_count == 0)
        clk_core_rate_protect(core->parent);

    core->protect_count++;
}

static int clk_core_prepare(struct clk_core *core)
{
    int ret = 0;

    lockdep_assert_held(&prepare_lock);

    if (!core)
        return 0;

    if (core->prepare_count == 0) {
        ret = clk_pm_runtime_get(core);
        if (ret)
            return ret;

        ret = clk_core_prepare(core->parent);
        if (ret)
            goto runtime_put;

        trace_clk_prepare(core);

        if (core->ops->prepare)
            ret = core->ops->prepare(core->hw);

        trace_clk_prepare_complete(core);

        if (ret)
            goto unprepare;
    }

    core->prepare_count++;

    /*
     * CLK_SET_RATE_GATE is a special case of clock protection
     * Instead of a consumer claiming exclusive rate control, it is
     * actually the provider which prevents any consumer from making any
     * operation which could result in a rate change or rate glitch while
     * the clock is prepared.
     */
    if (core->flags & CLK_SET_RATE_GATE)
        clk_core_rate_protect(core);

    return 0;
unprepare:
    clk_core_unprepare(core->parent);
runtime_put:
    clk_pm_runtime_put(core);
    return ret;
}

static int clk_core_prepare_lock(struct clk_core *core)
{
    int ret;

    clk_prepare_lock();
    ret = clk_core_prepare(core);
    clk_prepare_unlock();

    return ret;
}

/**
 * clk_prepare - prepare a clock source
 * @clk: the clk being prepared
 *
 * clk_prepare may sleep, which differentiates it from clk_enable.  In a simple
 * case, clk_prepare can be used instead of clk_enable to ungate a clk if the
 * operation may sleep.  One example is a clk which is accessed over I2c.  In
 * the complex case a clk ungate operation may require a fast and a slow part.
 * It is this reason that clk_prepare and clk_enable are not mutually
 * exclusive.  In fact clk_prepare must be called before clk_enable.
 * Returns 0 on success, -EERROR otherwise.
 */
int clk_prepare(struct clk *clk)
{
    if (!clk)
        return 0;

    return clk_core_prepare_lock(clk->core);
}

static unsigned long clk_enable_lock(void)
    __acquires(enable_lock)
{
    unsigned long flags;

    /*
     * On UP systems, spin_trylock_irqsave() always returns true, even if
     * we already hold the lock. So, in that case, we rely only on
     * reference counting.
     */
    if (!IS_ENABLED(CONFIG_SMP) ||
        !spin_trylock_irqsave(&enable_lock, flags)) {
        if (enable_owner == current) {
            enable_refcnt++;
            __acquire(enable_lock);
            if (!IS_ENABLED(CONFIG_SMP))
                local_save_flags(flags);
            return flags;
        }
        spin_lock_irqsave(&enable_lock, flags);
    }
    WARN_ON_ONCE(enable_owner != NULL);
    WARN_ON_ONCE(enable_refcnt != 0);
    enable_owner = current;
    enable_refcnt = 1;
    return flags;
}

static void clk_enable_unlock(unsigned long flags)
    __releases(enable_lock)
{
    WARN_ON_ONCE(enable_owner != current);
    WARN_ON_ONCE(enable_refcnt == 0);

    if (--enable_refcnt) {
        __release(enable_lock);
        return;
    }
    enable_owner = NULL;
    spin_unlock_irqrestore(&enable_lock, flags);
}

static void clk_core_disable(struct clk_core *core)
{
    lockdep_assert_held(&enable_lock);

    if (!core)
        return;

    if (WARN(core->enable_count == 0, "%s already disabled\n", core->name))
        return;

    if (WARN(core->enable_count == 1 && core->flags & CLK_IS_CRITICAL,
        "Disabling critical %s\n", core->name))
        return;

    if (--core->enable_count > 0)
        return;

    trace_clk_disable(core);

    if (core->ops->disable)
        core->ops->disable(core->hw);

    trace_clk_disable_complete(core);

    clk_core_disable(core->parent);
}

static int clk_core_enable(struct clk_core *core)
{
    int ret = 0;

    lockdep_assert_held(&enable_lock);

    if (!core)
        return 0;

    if (WARN(core->prepare_count == 0,
        "Enabling unprepared %s\n", core->name))
        return -ESHUTDOWN;

    if (core->enable_count == 0) {
        ret = clk_core_enable(core->parent);

        if (ret)
            return ret;

        trace_clk_enable(core);

        if (core->ops->enable)
            ret = core->ops->enable(core->hw);

        trace_clk_enable_complete(core);

        if (ret) {
            clk_core_disable(core->parent);
            return ret;
        }
    }

    core->enable_count++;
    return 0;
}

static int clk_core_enable_lock(struct clk_core *core)
{
    unsigned long flags;
    int ret;

    flags = clk_enable_lock();
    ret = clk_core_enable(core);
    clk_enable_unlock(flags);

    return ret;
}

/**
 * clk_enable - ungate a clock
 * @clk: the clk being ungated
 *
 * clk_enable must not sleep, which differentiates it from clk_prepare.  In a
 * simple case, clk_enable can be used instead of clk_prepare to ungate a clk
 * if the operation will never sleep.  One example is a SoC-internal clk which
 * is controlled via simple register writes.  In the complex case a clk ungate
 * operation may require a fast and a slow part.  It is this reason that
 * clk_enable and clk_prepare are not mutually exclusive.  In fact clk_prepare
 * must be called before clk_enable.  Returns 0 on success, -EERROR
 * otherwise.
 */
int clk_enable(struct clk *clk)
{
    if (!clk)
        return 0;

    return clk_core_enable_lock(clk->core);
}

/**
 * __clk_recalc_rates
 * @core: first clk in the subtree
 * @update_req: Whether req_rate should be updated with the new rate
 * @msg: notification type (see include/linux/clk.h)
 *
 * Walks the subtree of clks starting with clk and recalculates rates as it
 * goes.  Note that if a clk does not implement the .recalc_rate callback then
 * it is assumed that the clock will take on the rate of its parent.
 *
 * clk_recalc_rates also propagates the POST_RATE_CHANGE notification,
 * if necessary.
 */
static void __clk_recalc_rates(struct clk_core *core, bool update_req,
                   unsigned long msg)
{
    PANIC("");
}

static unsigned long clk_core_get_rate_recalc(struct clk_core *core)
{
    if (core && (core->flags & CLK_GET_RATE_NOCACHE))
        __clk_recalc_rates(core, false, 0);

    return clk_core_get_rate_nolock(core);
}

/**
 * clk_get_rate - return the rate of clk
 * @clk: the clk whose rate is being returned
 *
 * Simply returns the cached rate of the clk, unless CLK_GET_RATE_NOCACHE flag
 * is set, which means a recalc_rate will be issued. Can be called regardless of
 * the clock enabledness. If clk is NULL, or if an error occurred, then returns
 * 0.
 */
unsigned long clk_get_rate(struct clk *clk)
{
    unsigned long rate;

    if (!clk)
        return 0;

    clk_prepare_lock();
    rate = clk_core_get_rate_recalc(clk->core);
    clk_prepare_unlock();

    return rate;
}
