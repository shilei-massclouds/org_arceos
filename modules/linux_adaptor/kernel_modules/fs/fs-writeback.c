#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/kthread.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/tracepoint.h>
#include <linux/device.h>
#include <linux/memcontrol.h>
#include "internal.h"

/*
 * Include the creation of the trace points after defining the
 * wb_writeback_work structure and inline functions so that the definition
 * remains local to this file.
 */
#define CREATE_TRACE_POINTS
#include <trace/events/writeback.h>

#include "../adaptor.h"

static bool wb_io_lists_populated(struct bdi_writeback *wb)
{
    if (wb_has_dirty_io(wb)) {
        return false;
    } else {
        set_bit(WB_has_dirty_io, &wb->state);
        WARN_ON_ONCE(!wb->avg_write_bandwidth);
        atomic_long_add(wb->avg_write_bandwidth,
                &wb->bdi->tot_write_bandwidth);
        return true;
    }
}

static void wb_io_lists_depopulated(struct bdi_writeback *wb)
{
    if (wb_has_dirty_io(wb) && list_empty(&wb->b_dirty) &&
        list_empty(&wb->b_io) && list_empty(&wb->b_more_io)) {
        clear_bit(WB_has_dirty_io, &wb->state);
        WARN_ON_ONCE(atomic_long_sub_return(wb->avg_write_bandwidth,
                    &wb->bdi->tot_write_bandwidth) < 0);
    }
}

/*
 * This function is used when the first inode for this wb is marked dirty. It
 * wakes-up the corresponding bdi thread which should then take care of the
 * periodic background write-out of dirty inodes. Since the write-out would
 * starts only 'dirty_writeback_interval' centisecs from now anyway, we just
 * set up a timer which wakes the bdi thread up later.
 *
 * Note, we wouldn't bother setting up the timer, but this function is on the
 * fast-path (used by '__mark_inode_dirty()'), so we save few context switches
 * by delaying the wake-up.
 *
 * We have to be careful not to postpone flush work if it is scheduled for
 * earlier. Thus we use queue_delayed_work().
 */
static void wb_wakeup_delayed(struct bdi_writeback *wb)
{
    unsigned long timeout;

    timeout = msecs_to_jiffies(dirty_writeback_interval * 10);
    spin_lock_irq(&wb->work_lock);
    if (test_bit(WB_registered, &wb->state))
        queue_delayed_work(bdi_wq, &wb->dwork, timeout);
    spin_unlock_irq(&wb->work_lock);
}

void __inode_attach_wb(struct inode *inode, struct folio *folio)
{
    struct backing_dev_info *bdi = inode_to_bdi(inode);
    struct bdi_writeback *wb = NULL;

    pr_err("%s: inode_cgwb_enabled\n", __func__);
#if 0
    if (inode_cgwb_enabled(inode)) {
        struct cgroup_subsys_state *memcg_css;

        if (folio) {
            memcg_css = mem_cgroup_css_from_folio(folio);
            wb = wb_get_create(bdi, memcg_css, GFP_ATOMIC);
        } else {
            /* must pin memcg_css, see wb_get_create() */
            memcg_css = task_get_css(current, memory_cgrp_id);
            wb = wb_get_create(bdi, memcg_css, GFP_ATOMIC);
            css_put(memcg_css);
        }
    }
#endif

    if (!wb)
        wb = &bdi->wb;

    /*
     * There may be multiple instances of this function racing to
     * update the same inode.  Use cmpxchg() to tell the winner.
     */
    if (unlikely(cmpxchg(&inode->i_wb, NULL, wb)))
        wb_put(wb);
}

/**
 * locked_inode_to_wb_and_lock_list - determine a locked inode's wb and lock it
 * @inode: inode of interest with i_lock held
 *
 * Returns @inode's wb with its list_lock held.  @inode->i_lock must be
 * held on entry and is released on return.  The returned wb is guaranteed
 * to stay @inode's associated wb until its list_lock is released.
 */
static struct bdi_writeback *
locked_inode_to_wb_and_lock_list(struct inode *inode)
    __releases(&inode->i_lock)
    __acquires(&wb->list_lock)
{
    while (true) {
        struct bdi_writeback *wb = inode_to_wb(inode);

        /*
         * inode_to_wb() association is protected by both
         * @inode->i_lock and @wb->list_lock but list_lock nests
         * outside i_lock.  Drop i_lock and verify that the
         * association hasn't changed after acquiring list_lock.
         */
        wb_get(wb);
        spin_unlock(&inode->i_lock);
        spin_lock(&wb->list_lock);

        /* i_wb may have changed inbetween, can't use inode_to_wb() */
        if (likely(wb == inode->i_wb)) {
            wb_put(wb); /* @inode already has ref */
            return wb;
        }

        spin_unlock(&wb->list_lock);
        wb_put(wb);
        cpu_relax();
        spin_lock(&inode->i_lock);
    }
}

/**
 * inode_io_list_move_locked - move an inode onto a bdi_writeback IO list
 * @inode: inode to be moved
 * @wb: target bdi_writeback
 * @head: one of @wb->b_{dirty|io|more_io|dirty_time}
 *
 * Move @inode->i_io_list to @list of @wb and set %WB_has_dirty_io.
 * Returns %true if @inode is the first occupant of the !dirty_time IO
 * lists; otherwise, %false.
 */
static bool inode_io_list_move_locked(struct inode *inode,
                      struct bdi_writeback *wb,
                      struct list_head *head)
{
    assert_spin_locked(&wb->list_lock);
    assert_spin_locked(&inode->i_lock);
    WARN_ON_ONCE(inode->i_state & I_FREEING);

    printk("%s: step1 inode(%lx)\n", __func__, inode);
    list_move(&inode->i_io_list, head);

    printk("%s: step2\n", __func__);
    /* dirty_time doesn't count as dirty_io until expiration */
    if (head != &wb->b_dirty_time)
        return wb_io_lists_populated(wb);

    wb_io_lists_depopulated(wb);
    return false;
}

/**
 * __mark_inode_dirty - internal function to mark an inode dirty
 *
 * @inode: inode to mark
 * @flags: what kind of dirty, e.g. I_DIRTY_SYNC.  This can be a combination of
 *     multiple I_DIRTY_* flags, except that I_DIRTY_TIME can't be combined
 *     with I_DIRTY_PAGES.
 *
 * Mark an inode as dirty.  We notify the filesystem, then update the inode's
 * dirty flags.  Then, if needed we add the inode to the appropriate dirty list.
 *
 * Most callers should use mark_inode_dirty() or mark_inode_dirty_sync()
 * instead of calling this directly.
 *
 * CAREFUL!  We only add the inode to the dirty list if it is hashed or if it
 * refers to a blockdev.  Unhashed inodes will never be added to the dirty list
 * even if they are later hashed, as they will have been marked dirty already.
 *
 * In short, ensure you hash any inodes _before_ you start marking them dirty.
 *
 * Note that for blockdevs, inode->dirtied_when represents the dirtying time of
 * the block-special inode (/dev/hda1) itself.  And the ->dirtied_when field of
 * the kernel-internal blockdev inode represents the dirtying time of the
 * blockdev's pages.  This is why for I_DIRTY_PAGES we always use
 * page->mapping->host, so the page-dirtying time is recorded in the internal
 * blockdev inode.
 */
void __mark_inode_dirty(struct inode *inode, int flags)
{
    struct super_block *sb = inode->i_sb;
    int dirtytime = 0;
    struct bdi_writeback *wb = NULL;

    trace_writeback_mark_inode_dirty(inode, flags);

    if (flags & I_DIRTY_INODE) {
        PANIC("I_DIRTY_INODE");
    } else {
        /*
         * Else it's either I_DIRTY_PAGES, I_DIRTY_TIME, or nothing.
         * (We don't support setting both I_DIRTY_PAGES and I_DIRTY_TIME
         * in one call to __mark_inode_dirty().)
         */
        dirtytime = flags & I_DIRTY_TIME;
        WARN_ON_ONCE(dirtytime && flags != I_DIRTY_TIME);
    }

    /*
     * Paired with smp_mb() in __writeback_single_inode() for the
     * following lockless i_state test.  See there for details.
     */
    smp_mb();

    if ((inode->i_state & flags) == flags)
        return;

    spin_lock(&inode->i_lock);
    if ((inode->i_state & flags) != flags) {
        const int was_dirty = inode->i_state & I_DIRTY;

        inode_attach_wb(inode, NULL);

        inode->i_state |= flags;

        /*
         * Grab inode's wb early because it requires dropping i_lock and we
         * need to make sure following checks happen atomically with dirty
         * list handling so that we don't move inodes under flush worker's
         * hands.
         */
        if (!was_dirty) {
            wb = locked_inode_to_wb_and_lock_list(inode);
            spin_lock(&inode->i_lock);
        }

        /*
         * If the inode is queued for writeback by flush worker, just
         * update its dirty state. Once the flush worker is done with
         * the inode it will place it on the appropriate superblock
         * list, based upon its state.
         */
        if (inode->i_state & I_SYNC_QUEUED)
            goto out_unlock;

        /*
         * Only add valid (hashed) inodes to the superblock's
         * dirty list.  Add blockdev inodes as well.
         */
        if (!S_ISBLK(inode->i_mode)) {
            if (inode_unhashed(inode))
                goto out_unlock;
        }
        if (inode->i_state & I_FREEING)
            goto out_unlock;

        /*
         * If the inode was already on b_dirty/b_io/b_more_io, don't
         * reposition it (that would break b_dirty time-ordering).
         */
        if (!was_dirty) {
            struct list_head *dirty_list;
            bool wakeup_bdi = false;

            inode->dirtied_when = jiffies;
            if (dirtytime)
                inode->dirtied_time_when = jiffies;

            if (inode->i_state & I_DIRTY)
                dirty_list = &wb->b_dirty;
            else
                dirty_list = &wb->b_dirty_time;

        printk("%s: step1\n", __func__);
            wakeup_bdi = inode_io_list_move_locked(inode, wb,
                                   dirty_list);

        printk("%s: step2\n", __func__);
            spin_unlock(&wb->list_lock);
            spin_unlock(&inode->i_lock);
            trace_writeback_dirty_inode_enqueue(inode);

            /*
             * If this is the first dirty inode for this bdi,
             * we have to wake-up the corresponding bdi thread
             * to make sure background write-back happens
             * later.
             */
            if (wakeup_bdi &&
                (wb->bdi->capabilities & BDI_CAP_WRITEBACK))
                wb_wakeup_delayed(wb);
            return;
        }

        PANIC("flags!");
    }

    PANIC("");
out_unlock:
    if (wb)
        spin_unlock(&wb->list_lock);
    spin_unlock(&inode->i_lock);
}

/*
 * Handle writeback of dirty data for the device backed by this bdi. Also
 * reschedules periodically and does kupdated style flushing.
 */
void wb_workfn(struct work_struct *work)
{
    PANIC("");
}
