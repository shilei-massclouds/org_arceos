#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/clk.h>
#include <linux/clkdev.h>
#include <linux/clk-provider.h>
#include <linux/of.h>

#include "clk.h"
#include "../adaptor.h"

static LIST_HEAD(clocks);
static DEFINE_MUTEX(clocks_mutex);

/*
 * Find the correct struct clk for the device and connection ID.
 * We do slightly fuzzy matching here:
 *  An entry with a NULL ID is assumed to be a wildcard.
 *  If an entry has a device ID, it must match
 *  If an entry has a connection ID, it must match
 * Then we take the most specific entry - with the following
 * order of precedence: dev+con > dev only > con only.
 */
static struct clk_lookup *clk_find(const char *dev_id, const char *con_id)
{
    struct clk_lookup *p, *cl = NULL;
    int match, best_found = 0, best_possible = 0;

    if (dev_id)
        best_possible += 2;
    if (con_id)
        best_possible += 1;

    lockdep_assert_held(&clocks_mutex);

    list_for_each_entry(p, &clocks, node) {
        match = 0;
        if (p->dev_id) {
            if (!dev_id || strcmp(p->dev_id, dev_id))
                continue;
            match += 2;
        }
        if (p->con_id) {
            if (!con_id || strcmp(p->con_id, con_id))
                continue;
            match += 1;
        }

        if (match > best_found) {
            cl = p;
            if (match != best_possible)
                best_found = match;
            else
                break;
        }
    }
    return cl;
}

static struct clk *__clk_get_sys(struct device *dev, const char *dev_id,
                 const char *con_id)
{
#if 0
    struct clk_hw *hw = clk_find_hw(dev_id, con_id);

    return clk_hw_create_clk(dev, hw, dev_id, con_id);
#endif
    PANIC("");
}

struct clk *clk_get(struct device *dev, const char *con_id)
{
    const char *dev_id = dev ? dev_name(dev) : NULL;
    struct clk_hw *hw;

    if (dev && dev->of_node) {
        hw = of_clk_get_hw(dev->of_node, 0, con_id);
        if (!IS_ERR(hw) || PTR_ERR(hw) == -EPROBE_DEFER)
            return clk_hw_create_clk(dev, hw, dev_id, con_id);
    }

    return __clk_get_sys(dev, dev_id, con_id);
}

struct clk_hw *clk_find_hw(const char *dev_id, const char *con_id)
{
    struct clk_lookup *cl;
    struct clk_hw *hw = ERR_PTR(-ENOENT);

    mutex_lock(&clocks_mutex);
    cl = clk_find(dev_id, con_id);
    if (cl)
        hw = cl->clk_hw;
    mutex_unlock(&clocks_mutex);

    return hw;
}
