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

#include "../adaptor.h"

/*
 * bdi_lock protects bdi_tree and updates to bdi_list. bdi_list has RCU
 * reader side locking.
 */
DEFINE_SPINLOCK(bdi_lock);
static u64 bdi_id_cursor;
static struct rb_root bdi_tree = RB_ROOT;
LIST_HEAD(bdi_list);

/*
 * cgwb_lock protects bdi->cgwb_tree, blkcg->cgwb_list, offline_cgwbs and
 * memcg->cgwb_list.  bdi->cgwb_tree is also RCU protected.
 */
static DEFINE_SPINLOCK(cgwb_lock);

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

int bdi_register(struct backing_dev_info *bdi, const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = bdi_register_va(bdi, fmt, args);
    va_end(args);
    return ret;
}

static void cgwb_bdi_register(struct backing_dev_info *bdi)
{
    spin_lock_irq(&cgwb_lock);
    list_add_tail_rcu(&bdi->wb.bdi_node, &bdi->wb_list);
    spin_unlock_irq(&cgwb_lock);
}

static struct rb_node **bdi_lookup_rb_node(u64 id, struct rb_node **parentp)
{
    struct rb_node **p = &bdi_tree.rb_node;
    struct rb_node *parent = NULL;
    struct backing_dev_info *bdi;

    lockdep_assert_held(&bdi_lock);

    while (*p) {
        parent = *p;
        bdi = rb_entry(parent, struct backing_dev_info, rb_node);

        if (bdi->id > id)
            p = &(*p)->rb_left;
        else if (bdi->id < id)
            p = &(*p)->rb_right;
        else
            break;
    }

    if (parentp)
        *parentp = parent;
    return p;
}

int bdi_register_va(struct backing_dev_info *bdi, const char *fmt, va_list args)
{
    struct device *dev;
    struct rb_node *parent, **p;

    if (bdi->dev)   /* The driver needs to use separate queues per device */
        return 0;

    vsnprintf(bdi->dev_name, sizeof(bdi->dev_name), fmt, args);
    /*
    dev = device_create(&bdi_class, NULL, MKDEV(0, 0), bdi, bdi->dev_name);
    if (IS_ERR(dev))
        return PTR_ERR(dev);
    */

    cgwb_bdi_register(bdi);
    bdi->dev = dev;

    //bdi_debug_register(bdi, dev_name(dev));
    set_bit(WB_registered, &bdi->wb.state);

    spin_lock_bh(&bdi_lock);

    bdi->id = ++bdi_id_cursor;

    p = bdi_lookup_rb_node(bdi->id, &parent);
    rb_link_node(&bdi->rb_node, parent, p);
    rb_insert_color(&bdi->rb_node, &bdi_tree);

    list_add_tail_rcu(&bdi->bdi_list, &bdi_list);

    spin_unlock_bh(&bdi_lock);

    trace_writeback_bdi_register(bdi);
    return 0;
}

void bdi_set_owner(struct backing_dev_info *bdi, struct device *owner)
{
    WARN_ON_ONCE(bdi->owner);
    bdi->owner = owner;
    get_device(owner);
}
