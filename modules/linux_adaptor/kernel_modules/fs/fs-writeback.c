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

/*
 * Parameters for foreign inode detection, see wbc_detach_inode() to see
 * how they're used.
 *
 * These paramters are inherently heuristical as the detection target
 * itself is fuzzy.  All we want to do is detaching an inode from the
 * current owner if it's being written to by some other cgroups too much.
 *
 * The current cgroup writeback is built on the assumption that multiple
 * cgroups writing to the same inode concurrently is very rare and a mode
 * of operation which isn't well supported.  As such, the goal is not
 * taking too long when a different cgroup takes over an inode while
 * avoiding too aggressive flip-flops from occasional foreign writes.
 *
 * We record, very roughly, 2s worth of IO time history and if more than
 * half of that is foreign, trigger the switch.  The recording is quantized
 * to 16 slots.  To avoid tiny writes from swinging the decision too much,
 * writes smaller than 1/8 of avg size are ignored.
 */
#define WB_FRN_TIME_SHIFT   13  /* 1s = 2^13, upto 8 secs w/ 16bit */
#define WB_FRN_TIME_AVG_SHIFT   3   /* avg = avg * 7/8 + new * 1/8 */
#define WB_FRN_TIME_CUT_DIV 8   /* ignore rounds < avg / 8 */
#define WB_FRN_TIME_PERIOD  (2 * (1 << WB_FRN_TIME_SHIFT))  /* 2s */

#define WB_FRN_HIST_SLOTS   16  /* inode->i_wb_frn_history is 16bit */
#define WB_FRN_HIST_UNIT    (WB_FRN_TIME_PERIOD / WB_FRN_HIST_SLOTS)
                    /* each slot's duration is 2s / 16 */
#define WB_FRN_HIST_THR_SLOTS   (WB_FRN_HIST_SLOTS / 2)
                    /* if foreign slots >= 8, switch */
#define WB_FRN_HIST_MAX_SLOTS   (WB_FRN_HIST_THR_SLOTS / 2 + 1)
                    /* one round can affect upto 5 slots */
#define WB_FRN_MAX_IN_FLIGHT    1024    /* don't queue too many concurrently */

/*
 * Maximum inodes per isw.  A specific value has been chosen to make
 * struct inode_switch_wbs_context fit into 1024 bytes kmalloc.
 */
#define WB_MAX_INODES_PER_ISW  ((1024UL - sizeof(struct inode_switch_wbs_context)) \
                                / sizeof(struct inode *))

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

    printk("%s: step1\n", __func__);
    trace_writeback_mark_inode_dirty(inode, flags);

    if (flags & I_DIRTY_INODE) {
        /*
         * Inode timestamp update will piggback on this dirtying.
         * We tell ->dirty_inode callback that timestamps need to
         * be updated by setting I_DIRTY_TIME in flags.
         */
        if (inode->i_state & I_DIRTY_TIME) {
            spin_lock(&inode->i_lock);
            if (inode->i_state & I_DIRTY_TIME) {
                inode->i_state &= ~I_DIRTY_TIME;
                flags |= I_DIRTY_TIME;
            }
            spin_unlock(&inode->i_lock);
        }

        /*
         * Notify the filesystem about the inode being dirtied, so that
         * (if needed) it can update on-disk fields and journal the
         * inode.  This is only needed when the inode itself is being
         * dirtied now.  I.e. it's only needed for I_DIRTY_INODE, not
         * for just I_DIRTY_PAGES or I_DIRTY_TIME.
         */
        trace_writeback_dirty_inode_start(inode, flags);
        if (sb->s_op->dirty_inode)
            sb->s_op->dirty_inode(inode,
                flags & (I_DIRTY_INODE | I_DIRTY_TIME));
        trace_writeback_dirty_inode(inode, flags);

        /* I_DIRTY_INODE supersedes I_DIRTY_TIME. */
        flags &= ~I_DIRTY_TIME;
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

/**
 * inode_switch_wbs - change the wb association of an inode
 * @inode: target inode
 * @new_wb_id: ID of the new wb
 *
 * Switch @inode's wb association to the wb identified by @new_wb_id.  The
 * switching is performed asynchronously and may fail silently.
 */
static void inode_switch_wbs(struct inode *inode, int new_wb_id)
{
    PANIC("");
}

/**
 * wbc_attach_and_unlock_inode - associate wbc with target inode and unlock it
 * @wbc: writeback_control of interest
 * @inode: target inode
 *
 * @inode is locked and about to be written back under the control of @wbc.
 * Record @inode's writeback context into @wbc and unlock the i_lock.  On
 * writeback completion, wbc_detach_inode() should be called.  This is used
 * to track the cgroup writeback context.
 */
void wbc_attach_and_unlock_inode(struct writeback_control *wbc,
                 struct inode *inode)
{
    if (!inode_cgwb_enabled(inode)) {
        spin_unlock(&inode->i_lock);
        return;
    }

    wbc->wb = inode_to_wb(inode);
    wbc->inode = inode;

    printk("%s: No impl for wb_id.\n", __func__);
    //wbc->wb_id = wbc->wb->memcg_css->id;
    wbc->wb_lcand_id = inode->i_wb_frn_winner;
    wbc->wb_tcand_id = 0;
    wbc->wb_bytes = 0;
    wbc->wb_lcand_bytes = 0;
    wbc->wb_tcand_bytes = 0;

    wb_get(wbc->wb);
    spin_unlock(&inode->i_lock);

    /*
     * A dying wb indicates that either the blkcg associated with the
     * memcg changed or the associated memcg is dying.  In the first
     * case, a replacement wb should already be available and we should
     * refresh the wb immediately.  In the second case, trying to
     * refresh will keep failing.
     */
    if (unlikely(wb_dying(wbc->wb) && !css_is_dying(wbc->wb->memcg_css)))
        inode_switch_wbs(inode, wbc->wb_id);
}

/*
 * mark an inode as under writeback on the sb
 */
void sb_mark_inode_writeback(struct inode *inode)
{
    struct super_block *sb = inode->i_sb;
    unsigned long flags;

    if (list_empty(&inode->i_wb_list)) {
        spin_lock_irqsave(&sb->s_inode_wblist_lock, flags);
        if (list_empty(&inode->i_wb_list)) {
            list_add_tail(&inode->i_wb_list, &sb->s_inodes_wb);
            trace_sb_mark_inode_writeback(inode);
        }
        spin_unlock_irqrestore(&sb->s_inode_wblist_lock, flags);
    }
}

/**
 * wbc_account_cgroup_owner - account writeback to update inode cgroup ownership
 * @wbc: writeback_control of the writeback in progress
 * @folio: folio being written out
 * @bytes: number of bytes being written out
 *
 * @bytes from @folio are about to written out during the writeback
 * controlled by @wbc.  Keep the book for foreign inode detection.  See
 * wbc_detach_inode().
 */
void wbc_account_cgroup_owner(struct writeback_control *wbc, struct folio *folio,
                  size_t bytes)
{
    pr_err("%s: No impl.", __func__);
}

/*
 * clear an inode as under writeback on the sb
 */
void sb_clear_inode_writeback(struct inode *inode)
{
    struct super_block *sb = inode->i_sb;
    unsigned long flags;

    if (!list_empty(&inode->i_wb_list)) {
        spin_lock_irqsave(&sb->s_inode_wblist_lock, flags);
        if (!list_empty(&inode->i_wb_list)) {
            list_del_init(&inode->i_wb_list);
            trace_sb_clear_inode_writeback(inode);
        }
        spin_unlock_irqrestore(&sb->s_inode_wblist_lock, flags);
    }
}

/**
 * wbc_detach_inode - disassociate wbc from inode and perform foreign detection
 * @wbc: writeback_control of the just finished writeback
 *
 * To be called after a writeback attempt of an inode finishes and undoes
 * wbc_attach_and_unlock_inode().  Can be called under any context.
 *
 * As concurrent write sharing of an inode is expected to be very rare and
 * memcg only tracks page ownership on first-use basis severely confining
 * the usefulness of such sharing, cgroup writeback tracks ownership
 * per-inode.  While the support for concurrent write sharing of an inode
 * is deemed unnecessary, an inode being written to by different cgroups at
 * different points in time is a lot more common, and, more importantly,
 * charging only by first-use can too readily lead to grossly incorrect
 * behaviors (single foreign page can lead to gigabytes of writeback to be
 * incorrectly attributed).
 *
 * To resolve this issue, cgroup writeback detects the majority dirtier of
 * an inode and transfers the ownership to it.  To avoid unnecessary
 * oscillation, the detection mechanism keeps track of history and gives
 * out the switch verdict only if the foreign usage pattern is stable over
 * a certain amount of time and/or writeback attempts.
 *
 * On each writeback attempt, @wbc tries to detect the majority writer
 * using Boyer-Moore majority vote algorithm.  In addition to the byte
 * count from the majority voting, it also counts the bytes written for the
 * current wb and the last round's winner wb (max of last round's current
 * wb, the winner from two rounds ago, and the last round's majority
 * candidate).  Keeping track of the historical winner helps the algorithm
 * to semi-reliably detect the most active writer even when it's not the
 * absolute majority.
 *
 * Once the winner of the round is determined, whether the winner is
 * foreign or not and how much IO time the round consumed is recorded in
 * inode->i_wb_frn_history.  If the amount of recorded foreign IO time is
 * over a certain threshold, the switch verdict is given.
 */
void wbc_detach_inode(struct writeback_control *wbc)
{
    struct bdi_writeback *wb = wbc->wb;
    struct inode *inode = wbc->inode;
    unsigned long avg_time, max_bytes, max_time;
    u16 history;
    int max_id;

    if (!wb)
        return;

    history = inode->i_wb_frn_history;
    avg_time = inode->i_wb_frn_avg_time;

    /* pick the winner of this round */
    if (wbc->wb_bytes >= wbc->wb_lcand_bytes &&
        wbc->wb_bytes >= wbc->wb_tcand_bytes) {
        max_id = wbc->wb_id;
        max_bytes = wbc->wb_bytes;
    } else if (wbc->wb_lcand_bytes >= wbc->wb_tcand_bytes) {
        max_id = wbc->wb_lcand_id;
        max_bytes = wbc->wb_lcand_bytes;
    } else {
        max_id = wbc->wb_tcand_id;
        max_bytes = wbc->wb_tcand_bytes;
    }

    /*
     * Calculate the amount of IO time the winner consumed and fold it
     * into the running average kept per inode.  If the consumed IO
     * time is lower than avag / WB_FRN_TIME_CUT_DIV, ignore it for
     * deciding whether to switch or not.  This is to prevent one-off
     * small dirtiers from skewing the verdict.
     */
    max_time = DIV_ROUND_UP((max_bytes >> PAGE_SHIFT) << WB_FRN_TIME_SHIFT,
                wb->avg_write_bandwidth);
    if (avg_time)
        avg_time += (max_time >> WB_FRN_TIME_AVG_SHIFT) -
                (avg_time >> WB_FRN_TIME_AVG_SHIFT);
    else
        avg_time = max_time;    /* immediate catch up on first run */

    if (max_time >= avg_time / WB_FRN_TIME_CUT_DIV) {
        int slots;

        /*
         * The switch verdict is reached if foreign wb's consume
         * more than a certain proportion of IO time in a
         * WB_FRN_TIME_PERIOD.  This is loosely tracked by 16 slot
         * history mask where each bit represents one sixteenth of
         * the period.  Determine the number of slots to shift into
         * history from @max_time.
         */
        slots = min(DIV_ROUND_UP(max_time, WB_FRN_HIST_UNIT),
                (unsigned long)WB_FRN_HIST_MAX_SLOTS);
        history <<= slots;
        if (wbc->wb_id != max_id)
            history |= (1U << slots) - 1;

        if (history)
            trace_inode_foreign_history(inode, wbc, history);

        /*
         * Switch if the current wb isn't the consistent winner.
         * If there are multiple closely competing dirtiers, the
         * inode may switch across them repeatedly over time, which
         * is okay.  The main goal is avoiding keeping an inode on
         * the wrong wb for an extended period of time.
         */
        if (hweight16(history) > WB_FRN_HIST_THR_SLOTS)
            inode_switch_wbs(inode, max_id);
    }

    /*
     * Multiple instances of this function may race to update the
     * following fields but we don't mind occassional inaccuracies.
     */
    inode->i_wb_frn_winner = max_id;
    inode->i_wb_frn_avg_time = min(avg_time, (unsigned long)U16_MAX);
    inode->i_wb_frn_history = history;

    wb_put(wbc->wb);
    wbc->wb = NULL;
}

/*
 * Write out an inode's dirty data and metadata on-demand, i.e. separately from
 * the regular batched writeback done by the flusher threads in
 * writeback_sb_inodes().  @wbc controls various aspects of the write, such as
 * whether it is a data-integrity sync (%WB_SYNC_ALL) or not (%WB_SYNC_NONE).
 *
 * To prevent the inode from going away, either the caller must have a reference
 * to the inode, or the inode must have I_WILL_FREE or I_FREEING set.
 */
static int writeback_single_inode(struct inode *inode,
                  struct writeback_control *wbc)
{
    PANIC("");
}

/*
 * Wait for writeback on an inode to complete. Called with i_lock held.
 * Caller must make sure inode cannot go away when we drop i_lock.
 */
void inode_wait_for_writeback(struct inode *inode)
{
    struct wait_bit_queue_entry wqe;
    struct wait_queue_head *wq_head;

    assert_spin_locked(&inode->i_lock);

    if (!(inode->i_state & I_SYNC))
        return;

    wq_head = inode_bit_waitqueue(&wqe, inode, __I_SYNC);
    for (;;) {
        prepare_to_wait_event(wq_head, &wqe.wq_entry, TASK_UNINTERRUPTIBLE);
        /* Checking I_SYNC with inode->i_lock guarantees memory ordering. */
        if (!(inode->i_state & I_SYNC))
            break;
        spin_unlock(&inode->i_lock);
        schedule();
        spin_lock(&inode->i_lock);
    }
    finish_wait(wq_head, &wqe.wq_entry);
}

/**
 * write_inode_now  -   write an inode to disk
 * @inode: inode to write to disk
 * @sync: whether the write should be synchronous or not
 *
 * This function commits an inode to disk immediately if it is dirty. This is
 * primarily needed by knfsd.
 *
 * The caller must either have a ref on the inode or must have set I_WILL_FREE.
 */
int write_inode_now(struct inode *inode, int sync)
{
    struct writeback_control wbc = {
        .nr_to_write = LONG_MAX,
        .sync_mode = sync ? WB_SYNC_ALL : WB_SYNC_NONE,
        .range_start = 0,
        .range_end = LLONG_MAX,
    };

    printk("%s: ..\n", __func__);
    if (!mapping_can_writeback(inode->i_mapping))
        wbc.nr_to_write = 0;

    might_sleep();
    return writeback_single_inode(inode, &wbc);
}
