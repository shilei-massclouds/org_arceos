#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/smp.h>

#include "blk.h"
#include "blk-mq.h"

void blk_mq_hctx_kobj_init(struct blk_mq_hw_ctx *hctx)
{
    pr_err("%s: No impl.", __func__);
    //kobject_init(&hctx->kobj, &blk_mq_hw_ktype);
}
