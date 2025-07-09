#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/pagemap.h>

#include "booter.h"

/*
 * Passed into wb_writeback(), essentially a subset of writeback_control
 */
struct wb_writeback_work {
    long nr_pages;
    struct super_block *sb;
    enum writeback_sync_modes sync_mode;
    unsigned int tagged_writepages:1;
    unsigned int for_kupdate:1;
    unsigned int range_cyclic:1;
    unsigned int for_background:1;
    unsigned int for_sync:1;    /* sync(2) WB_SYNC_ALL writeback */
    unsigned int auto_free:1;   /* free on completion */
    enum wb_reason reason;      /* why was writeback initiated? */

    struct list_head list;      /* pending work list */
    struct wb_completion *done; /* set if the caller waits */
};

static inline struct inode *wb_inode(struct list_head *head)
{
    return list_entry(head, struct inode, i_io_list);
}

/*
 * Sleep until I_SYNC is cleared. This function must be called with i_lock
 * held and drops it. It is aimed for callers not holding any inode reference
 * so once i_lock is dropped, inode can go away.
 */
static void inode_sleep_on_writeback(struct inode *inode)
    __releases(inode->i_lock)
{
    DEFINE_WAIT(wait);
    wait_queue_head_t *wqh = bit_waitqueue(&inode->i_state, __I_SYNC);
    int sleep;

    prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
    sleep = inode->i_state & I_SYNC;
    spin_unlock(&inode->i_lock);
    if (sleep)
        schedule();
    finish_wait(wqh, &wait);
}

/*
 * Add in the number of potentially dirty inodes, because each inode
 * write can dirty pagecache in the underlying blockdev.
 */
static unsigned long get_nr_dirty_pages(void)
{
    /*
    return global_node_page_state(NR_FILE_DIRTY) +
        get_nr_dirty_inodes();
        */
    log_error("%s: No impl.\n", __func__);
    return 1;
}

/*
 * Queue all expired dirty inodes for io, eldest first.
 * Before
 *         newly dirtied     b_dirty    b_io    b_more_io
 *         =============>    gf         edc     BA
 * After
 *         newly dirtied     b_dirty    b_io    b_more_io
 *         =============>    g          fBAedc
 *                                           |
 *                                           +--> dequeue for IO
 */
static void queue_io(struct bdi_writeback *wb, struct wb_writeback_work *work,
             unsigned long dirtied_before)
{
#if 0
    int moved;
    unsigned long time_expire_jif = dirtied_before;

    assert_spin_locked(&wb->list_lock);
    list_splice_init(&wb->b_more_io, &wb->b_io);
    moved = move_expired_inodes(&wb->b_dirty, &wb->b_io, dirtied_before);
    if (!work->for_sync)
        time_expire_jif = jiffies - dirtytime_expire_interval * HZ;
    moved += move_expired_inodes(&wb->b_dirty_time, &wb->b_io,
                     time_expire_jif);
    if (moved)
        wb_io_lists_populated(wb);
    trace_writeback_queue_io(wb, work, dirtied_before, moved);
#endif

    log_error("%s: No impl.\n", __func__);
}

/*
 * Write a portion of b_io inodes which belong to @sb.
 *
 * Return the number of pages and/or inodes written.
 *
 * NOTE! This is called with wb->list_lock held, and will
 * unlock and relock that for each inode it ends up doing
 * IO for.
 */
static long writeback_sb_inodes(struct super_block *sb,
                struct bdi_writeback *wb,
                struct wb_writeback_work *work)
{
    booter_panic("%s: No impl.\n", __func__);
}

static long __writeback_inodes_wb(struct bdi_writeback *wb,
                  struct wb_writeback_work *work)
{
    unsigned long start_time = jiffies;
    long wrote = 0;

    printk("%s: ...\n", __func__);
    while (!list_empty(&wb->b_io)) {
        booter_panic("loop");
    }

    /* Leave any unwritten inodes on b_io */
    return wrote;
}

/*
 * Explicit flushing or periodic writeback of "old" data.
 *
 * Define "old": the first time one of an inode's pages is dirtied, we mark the
 * dirtying-time in the inode's address_space.  So this periodic writeback code
 * just walks the superblock inode list, writing back any inodes which are
 * older than a specific point in time.
 *
 * Try to run once per dirty_writeback_interval.  But if a writeback event
 * takes longer than a dirty_writeback_interval interval, then leave a
 * one-second gap.
 *
 * dirtied_before takes precedence over nr_to_write.  So we'll only write back
 * all dirty pages if they are all attached to "old" mappings.
 */
static long wb_writeback(struct bdi_writeback *wb,
             struct wb_writeback_work *work)
{
    unsigned long wb_start = jiffies;
    long nr_pages = work->nr_pages;
    unsigned long dirtied_before = jiffies;
    struct inode *inode;
    long progress;
    struct blk_plug plug;

    blk_start_plug(&plug);
    spin_lock(&wb->list_lock);
    for (;;) {
        /*
         * Stop writeback when nr_pages has been consumed
         */
        if (work->nr_pages <= 0)
            break;

        /*
         * Background writeout and kupdate-style writeback may
         * run forever. Stop them if there is other work to do
         * so that e.g. sync can proceed. They'll be restarted
         * after the other works are all done.
         */
        if ((work->for_background || work->for_kupdate) &&
            !list_empty(&wb->work_list))
            break;

        /*
         * For background writeout, stop when we are below the
         * background dirty threshold
         */
        if (work->for_background && !wb_over_bg_thresh(wb))
            break;

        /*
         * Kupdate and background works are special and we want to
         * include all inodes that need writing. Livelock avoidance is
         * handled by these works yielding to any other work so we are
         * safe.
         */
        if (work->for_kupdate) {
            dirtied_before = jiffies -
                msecs_to_jiffies(dirty_expire_interval * 10);
        } else if (work->for_background)
            dirtied_before = jiffies;

        if (list_empty(&wb->b_io))
            queue_io(wb, work, dirtied_before);
        if (work->sb)
            progress = writeback_sb_inodes(work->sb, wb, work);
        else
            progress = __writeback_inodes_wb(wb, work);

        wb_update_bandwidth(wb, wb_start);

        /*
         * Did we write something? Try for more
         *
         * Dirty inodes are moved to b_io for writeback in batches.
         * The completion of the current batch does not necessarily
         * mean the overall work is done. So we keep looping as long
         * as made some progress on cleaning pages or inodes.
         */
        if (progress)
            continue;
        /*
         * No more inodes for IO, bail
         */
        if (list_empty(&wb->b_more_io))
            break;

        /*
         * Nothing written. Wait for some inode to
         * become available for writeback. Otherwise
         * we'll just busyloop.
         */
        inode = wb_inode(wb->b_more_io.prev);
        spin_lock(&inode->i_lock);
        spin_unlock(&wb->list_lock);
        /* This function drops i_lock... */
        inode_sleep_on_writeback(inode);
        spin_lock(&wb->list_lock);
    }
    spin_unlock(&wb->list_lock);
    blk_finish_plug(&plug);

    return nr_pages - work->nr_pages;
}

static void finish_writeback_work(struct bdi_writeback *wb,
                  struct wb_writeback_work *work)
{
    booter_panic("%s: No impl.\n", __func__);
}

static struct bdi_writeback *
locked_inode_to_wb_and_lock_list(struct inode *inode)
    __releases(&inode->i_lock)
    __acquires(&wb->list_lock)
{
    struct bdi_writeback *wb = inode_to_wb(inode);

    spin_unlock(&inode->i_lock);
    spin_lock(&wb->list_lock);
    return wb;
}

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

    printk("%s: 1\n", __func__);
    list_move(&inode->i_io_list, head);

    printk("%s: 3\n", __func__);
    /* dirty_time doesn't count as dirty_io until expiration */
    if (head != &wb->b_dirty_time)
        return wb_io_lists_populated(wb);

    wb_io_lists_depopulated(wb);
    return false;
}

/**
 * __mark_inode_dirty - internal function
 *
 * @inode: inode to mark
 * @flags: what kind of dirty (i.e. I_DIRTY_SYNC)
 *
 * Mark an inode as dirty. Callers should use mark_inode_dirty or
 * mark_inode_dirty_sync.
 *
 * Put the inode on the super block's dirty list.
 *
 * CAREFUL! We mark it dirty unconditionally, but move it onto the
 * dirty list only if it is hashed or if it refers to a blockdev.
 * If it was not hashed, it will never be added to the dirty list
 * even if it is later hashed, as it will have been marked dirty already.
 *
 * In short, make sure you hash any inodes _before_ you start marking
 * them dirty.
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
    int dirtytime;

    printk("%s: step1 flags(%x)\n", __func__, flags);
    //trace_writeback_mark_inode_dirty(inode, flags);

    /*
     * Don't do this for I_DIRTY_PAGES - that doesn't actually
     * dirty the inode itself
     */
    if (flags & (I_DIRTY_INODE | I_DIRTY_TIME)) {
    printk("%s: (I_DIRTY_INODE | I_DIRTY_TIME) (%lx)\n", __func__, sb->s_op->dirty_inode);
        //trace_writeback_dirty_inode_start(inode, flags);

        if (sb->s_op->dirty_inode)
            sb->s_op->dirty_inode(inode, flags);

        //trace_writeback_dirty_inode(inode, flags);
    }
    if (flags & I_DIRTY_INODE)
        flags &= ~I_DIRTY_TIME;
    dirtytime = flags & I_DIRTY_TIME;

    /*
     * Paired with smp_mb() in __writeback_single_inode() for the
     * following lockless i_state test.  See there for details.
     */
    smp_mb();

    if (((inode->i_state & flags) == flags) ||
        (dirtytime && (inode->i_state & I_DIRTY_INODE)))
        return;

    /*
    if (unlikely(block_dump))
        block_dump___mark_inode_dirty(inode);
        */

    spin_lock(&inode->i_lock);
    if (dirtytime && (inode->i_state & I_DIRTY_INODE))
        goto out_unlock_inode;

    printk("%s: step2 i_state(%x) flags(%x)\n", __func__, inode->i_state, flags);
    if ((inode->i_state & flags) != flags) {
        const int was_dirty = inode->i_state & I_DIRTY;

        inode_attach_wb(inode, NULL);

        if (flags & I_DIRTY_INODE)
            inode->i_state &= ~I_DIRTY_TIME;
        inode->i_state |= flags;

        /*
         * If the inode is queued for writeback by flush worker, just
         * update its dirty state. Once the flush worker is done with
         * the inode it will place it on the appropriate superblock
         * list, based upon its state.
         */
        if (inode->i_state & I_SYNC_QUEUED)
            goto out_unlock_inode;

        /*
         * Only add valid (hashed) inodes to the superblock's
         * dirty list.  Add blockdev inodes as well.
         */
        if (!S_ISBLK(inode->i_mode)) {
            if (inode_unhashed(inode))
                goto out_unlock_inode;
        }
        if (inode->i_state & I_FREEING)
            goto out_unlock_inode;

        /*
         * If the inode was already on b_dirty/b_io/b_more_io, don't
         * reposition it (that would break b_dirty time-ordering).
         */
        if (!was_dirty) {
            struct bdi_writeback *wb;
            struct list_head *dirty_list;
            bool wakeup_bdi = false;

            wb = locked_inode_to_wb_and_lock_list(inode);
    printk("%s: 0.1 wb(%lx)\n", __func__, wb);

            WARN(bdi_cap_writeback_dirty(wb->bdi) &&
                 !test_bit(WB_registered, &wb->state),
                 "bdi-%s not registered\n", bdi_dev_name(wb->bdi));
    printk("----------------------------------- %s: 0.1\n", __func__);

            inode->dirtied_when = jiffies;
            if (dirtytime)
                inode->dirtied_time_when = jiffies;

            if (inode->i_state & I_DIRTY)
                dirty_list = &wb->b_dirty;
            else
                dirty_list = &wb->b_dirty_time;

    printk("%s: 0.2\n", __func__);
            wakeup_bdi = inode_io_list_move_locked(inode, wb,
                                   dirty_list);

            spin_unlock(&wb->list_lock);
            //trace_writeback_dirty_inode_enqueue(inode);

    printk("%s: 0.3\n", __func__);
            /*
             * If this is the first dirty inode for this bdi,
             * we have to wake-up the corresponding bdi thread
             * to make sure background write-back happens
             * later.
             */
            if (bdi_cap_writeback_dirty(wb->bdi) && wakeup_bdi)
                wb_wakeup_delayed(wb);
            return;
        }
    }

out_unlock_inode:
    spin_unlock(&inode->i_lock);
}

/*
 * Return the next wb_writeback_work struct that hasn't been processed yet.
 */
static struct wb_writeback_work *get_next_work_item(struct bdi_writeback *wb)
{
    struct wb_writeback_work *work = NULL;

    spin_lock_bh(&wb->work_lock);
    if (!list_empty(&wb->work_list)) {
        work = list_entry(wb->work_list.next,
                  struct wb_writeback_work, list);
        list_del_init(&work->list);
    }
    spin_unlock_bh(&wb->work_lock);
    return work;
}

static long wb_check_start_all(struct bdi_writeback *wb)
{
    long nr_pages;

    if (!test_bit(WB_start_all, &wb->state))
        return 0;

    booter_panic("Here!");
}

static long wb_check_old_data_flush(struct bdi_writeback *wb)
{
    unsigned long expired;
    long nr_pages;

    /*
     * When set to zero, disable periodic writeback
     */
    if (!dirty_writeback_interval)
        return 0;

    expired = wb->last_old_flush +
            msecs_to_jiffies(dirty_writeback_interval * 10);
    /*
    if (time_before(jiffies, expired))
        return 0;
        */

    wb->last_old_flush = jiffies;
    nr_pages = get_nr_dirty_pages();

    if (nr_pages) {
        struct wb_writeback_work work = {
            .nr_pages   = nr_pages,
            .sync_mode  = WB_SYNC_NONE,
            .for_kupdate    = 1,
            .range_cyclic   = 1,
            .reason     = WB_REASON_PERIODIC,
        };

        return wb_writeback(wb, &work);
    }

    return 0;
}

static long wb_check_background_flush(struct bdi_writeback *wb)
{
    if (wb_over_bg_thresh(wb)) {

        struct wb_writeback_work work = {
            .nr_pages   = LONG_MAX,
            .sync_mode  = WB_SYNC_NONE,
            .for_background = 1,
            .range_cyclic   = 1,
            .reason     = WB_REASON_BACKGROUND,
        };

        return wb_writeback(wb, &work);
    }

    return 0;
}

/*
 * Retrieve work items and do the writeback they describe
 */
static long wb_do_writeback(struct bdi_writeback *wb)
{
    struct wb_writeback_work *work;
    long wrote = 0;

    set_bit(WB_writeback_running, &wb->state);
    while ((work = get_next_work_item(wb)) != NULL) {
        wrote += wb_writeback(wb, work);
        finish_writeback_work(wb, work);
    }

    /*
     * Check for a flush-everything request
     */
    wrote += wb_check_start_all(wb);

    /*
     * Check for periodic writeback, kupdated() style
     */
    wrote += wb_check_old_data_flush(wb);
    wrote += wb_check_background_flush(wb);
    clear_bit(WB_writeback_running, &wb->state);

    return wrote;
}

/*
 * Handle writeback of dirty data for the device backed by this bdi. Also
 * reschedules periodically and does kupdated style flushing.
 */
void wb_workfn(struct work_struct *work)
{
    struct bdi_writeback *wb = container_of(to_delayed_work(work),
                        struct bdi_writeback, dwork);
    long pages_written;

    /*
     * The normal path.  Keep writing back @wb until its
     * work_list is empty.  Note that this path is also taken
     * if @wb is shutting down even when we're running off the
     * rescuer as work_list needs to be drained.
     */
    do {
        pages_written = wb_do_writeback(wb);
    } while (!list_empty(&wb->work_list));
}
