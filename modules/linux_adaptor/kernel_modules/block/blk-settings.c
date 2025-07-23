#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/blk-integrity.h>
#include <linux/pagemap.h>
#include <linux/backing-dev-defs.h>
#include <linux/gcd.h>
#include <linux/lcm.h>
#include <linux/jiffies.h>
#include <linux/gfp.h>
#include <linux/dma-mapping.h>

#include "blk.h"
#include "blk-rq-qos.h"
#include "blk-wbt.h"

/*
 * Check that the limits in lim are valid, initialize defaults for unset
 * values, and cap values based on others where needed.
 */
static int blk_validate_limits(struct queue_limits *lim)
{
    pr_err("%s: No impl.", __func__);
}

/*
 * Set the default limits for a newly allocated queue.  @lim contains the
 * initial limits set by the driver, which could be no limit in which case
 * all fields are cleared to zero.
 */
int blk_set_default_limits(struct queue_limits *lim)
{
    /*
     * Most defaults are set by capping the bounds in blk_validate_limits,
     * but max_user_discard_sectors is special and needs an explicit
     * initialization to the max value here.
     */
    lim->max_user_discard_sectors = UINT_MAX;
    return blk_validate_limits(lim);
}
