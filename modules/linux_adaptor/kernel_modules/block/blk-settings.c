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
    pr_notice("%s: No impl.", __func__);
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

void blk_apply_bdi_limits(struct backing_dev_info *bdi,
        struct queue_limits *lim)
{
    /*
     * For read-ahead of large files to be effective, we need to read ahead
     * at least twice the optimal I/O size.
     *
     * There is no hardware limitation for the read-ahead size and the user
     * might have increased the read-ahead size through sysfs, so don't ever
     * decrease it.
     */
    bdi->ra_pages = max3(bdi->ra_pages,
                lim->io_opt * 2 / PAGE_SIZE,
                VM_READAHEAD_PAGES);
    bdi->io_pages = lim->max_sectors >> PAGE_SECTORS_SHIFT;
}
