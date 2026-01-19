// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/page_reporting.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>

#include "page_reporting.h"
#include "internal.h"

/* Initialize to an unsupported value */
unsigned int page_reporting_order = -1;

static DEFINE_MUTEX(page_reporting_mutex);
DEFINE_STATIC_KEY_FALSE(page_reporting_enabled);

/* notify prdev of free page reporting request */
void __page_reporting_notify(void)
{
#if 0
    struct page_reporting_dev_info *prdev;

    /*
     * We use RCU to protect the pr_dev_info pointer. In almost all
     * cases this should be present, however in the unlikely case of
     * a shutdown this will be NULL and we should exit.
     */
    rcu_read_lock();
    prdev = rcu_dereference(pr_dev_info);
    if (likely(prdev))
        __page_reporting_request(prdev);

    rcu_read_unlock();
#endif
    pr_notice("%s: No impl.", __func__);
}
