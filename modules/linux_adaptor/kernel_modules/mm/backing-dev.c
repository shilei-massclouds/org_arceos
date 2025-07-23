#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/rbtree.h>
#include <linux/kthread.h>
#include <linux/backing-dev.h>
#include <linux/blk-cgroup.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/device.h>
#include <trace/events/writeback.h>
#include "internal.h"

/*
 * Initial write bandwidth: 100 MB/s
 */
#define INIT_BW     (100 << (20 - PAGE_SHIFT))

static int wb_init(struct bdi_writeback *wb, struct backing_dev_info *bdi,
           gfp_t gfp)
{
    int err;

    memset(wb, 0, sizeof(*wb));

    wb->bdi = bdi;
    wb->last_old_flush = jiffies;
    INIT_LIST_HEAD(&wb->b_dirty);
    INIT_LIST_HEAD(&wb->b_io);
    INIT_LIST_HEAD(&wb->b_more_io);
    INIT_LIST_HEAD(&wb->b_dirty_time);
    spin_lock_init(&wb->list_lock);

    atomic_set(&wb->writeback_inodes, 0);
    wb->bw_time_stamp = jiffies;
    wb->balanced_dirty_ratelimit = INIT_BW;
    wb->dirty_ratelimit = INIT_BW;
    wb->write_bandwidth = INIT_BW;
    wb->avg_write_bandwidth = INIT_BW;

    spin_lock_init(&wb->work_lock);
    INIT_LIST_HEAD(&wb->work_list);
#if 0
    INIT_DELAYED_WORK(&wb->dwork, wb_workfn);
    INIT_DELAYED_WORK(&wb->bw_dwork, wb_update_bandwidth_workfn);

    err = fprop_local_init_percpu(&wb->completions, gfp);
    if (err)
        return err;

    err = percpu_counter_init_many(wb->stat, 0, gfp, NR_WB_STAT_ITEMS);
    if (err)
        fprop_local_destroy_percpu(&wb->completions);
#endif
    pr_err("%s: No impl.", __func__);

    return err;
}

static int cgwb_bdi_init(struct backing_dev_info *bdi)
{
    int ret;

    INIT_RADIX_TREE(&bdi->cgwb_tree, GFP_ATOMIC);
    mutex_init(&bdi->cgwb_release_mutex);
    init_rwsem(&bdi->wb_switch_rwsem);

    ret = wb_init(&bdi->wb, bdi, GFP_KERNEL);
    if (!ret) {
#if 0
        bdi->wb.memcg_css = &root_mem_cgroup->css;
        bdi->wb.blkcg_css = blkcg_root_css;
#endif
        pr_err("%s: No impl.", __func__);
    }
    return ret;
}

int bdi_init(struct backing_dev_info *bdi)
{
    bdi->dev = NULL;

    kref_init(&bdi->refcnt);
    bdi->min_ratio = 0;
    bdi->max_ratio = 100 * BDI_RATIO_SCALE;
    bdi->max_prop_frac = FPROP_FRAC_BASE;
    INIT_LIST_HEAD(&bdi->bdi_list);
    INIT_LIST_HEAD(&bdi->wb_list);
    init_waitqueue_head(&bdi->wb_waitq);
    bdi->last_bdp_sleep = jiffies;

    return cgwb_bdi_init(bdi);
}

struct backing_dev_info *bdi_alloc(int node_id)
{
    struct backing_dev_info *bdi;

    bdi = kzalloc_node(sizeof(*bdi), GFP_KERNEL, node_id);
    if (!bdi)
        return NULL;

    if (bdi_init(bdi)) {
        kfree(bdi);
        return NULL;
    }
    bdi->capabilities = BDI_CAP_WRITEBACK | BDI_CAP_WRITEBACK_ACCT;
    bdi->ra_pages = VM_READAHEAD_PAGES;
    bdi->io_pages = VM_READAHEAD_PAGES;
    //timer_setup(&bdi->laptop_mode_wb_timer, laptop_mode_timer_fn, 0);
    return bdi;
}
