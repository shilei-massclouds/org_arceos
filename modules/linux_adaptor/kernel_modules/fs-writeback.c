#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/pagemap.h>

#include "booter.h"
#include "fs/internal.h"

/*
 * 4MB minimal write chunk size
 */
#define MIN_WRITEBACK_PAGES (4096UL >> (PAGE_SHIFT - 10))

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

/**
 * inode_to_wb_and_lock_list - determine an inode's wb and lock it
 * @inode: inode of interest
 *
 * Same as locked_inode_to_wb_and_lock_list() but @inode->i_lock isn't held
 * on entry.
 */
static struct bdi_writeback *inode_to_wb_and_lock_list(struct inode *inode)
    __acquires(&wb->list_lock)
{
    spin_lock(&inode->i_lock);
    return locked_inode_to_wb_and_lock_list(inode);
}

/*
 * If an inode is constantly having its pages dirtied, but then the
 * updates stop dirtytime_expire_interval seconds in the past, it's
 * possible for the worst case time between when an inode has its
 * timestamps updated and when they finally get written out to be two
 * dirtytime_expire_intervals.  We set the default to 12 hours (in
 * seconds), which means most of the time inodes will have their
 * timestamps written to disk after 12 hours, but in the worst case a
 * few inodes might not their timestamps updated for 24 hours.
 */
unsigned int dirtytime_expire_interval = 12 * 60 * 60;

static inline struct inode *wb_inode(struct list_head *head)
{
    return list_entry(head, struct inode, i_io_list);
}

/*
 * Redirty an inode: set its when-it-was dirtied timestamp and move it to the
 * furthest end of its superblock's dirty-inode list.
 *
 * Before stamping the inode's ->dirtied_when, we check to see whether it is
 * already the most-recently-dirtied inode on the b_dirty list.  If that is
 * the case then the inode must have been redirtied while it was being written
 * out and we don't reset its dirtied_when.
 */
static void redirty_tail_locked(struct inode *inode, struct bdi_writeback *wb)
{
    assert_spin_locked(&inode->i_lock);

    if (!list_empty(&wb->b_dirty)) {
        struct inode *tail;

        tail = wb_inode(wb->b_dirty.next);
        if (time_before(inode->dirtied_when, tail->dirtied_when))
            inode->dirtied_when = jiffies;
    }
    inode_io_list_move_locked(inode, wb, &wb->b_dirty);
    inode->i_state &= ~I_SYNC_QUEUED;
}

static void redirty_tail(struct inode *inode, struct bdi_writeback *wb)
{
    spin_lock(&inode->i_lock);
    redirty_tail_locked(inode, wb);
    spin_unlock(&inode->i_lock);
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

static bool inode_dirtied_after(struct inode *inode, unsigned long t)
{
#if 0
    bool ret = time_after(inode->dirtied_when, t);
#ifndef CONFIG_64BIT
    /*
     * For inodes being constantly redirtied, dirtied_when can get stuck.
     * It _appears_ to be in the future, but is actually in distant past.
     * This test is necessary to prevent such wrapped-around relative times
     * from permanently stopping the whole bdi writeback.
     */
    ret = ret && time_before_eq(inode->dirtied_when, jiffies);
#endif
    return ret;
#endif
    log_error("%s: No impl.", __func__);
    return false;
}

/*
 * Move expired (dirtied before dirtied_before) dirty inodes from
 * @delaying_queue to @dispatch_queue.
 */
static int move_expired_inodes(struct list_head *delaying_queue,
                   struct list_head *dispatch_queue,
                   unsigned long dirtied_before)
{
    LIST_HEAD(tmp);
    struct list_head *pos, *node;
    struct super_block *sb = NULL;
    struct inode *inode;
    int do_sb_sort = 0;
    int moved = 0;

    printk("%s: ...\n", __func__);

    while (!list_empty(delaying_queue)) {
        inode = wb_inode(delaying_queue->prev);
        if (inode_dirtied_after(inode, dirtied_before))
            break;
        list_move(&inode->i_io_list, &tmp);
        moved++;
        spin_lock(&inode->i_lock);
        inode->i_state |= I_SYNC_QUEUED;
        spin_unlock(&inode->i_lock);
        if (sb_is_blkdev_sb(inode->i_sb))
            continue;
        if (sb && sb != inode->i_sb)
            do_sb_sort = 1;
        sb = inode->i_sb;
    }

    /* just one sb in list, splice to dispatch_queue and we're done */
    if (!do_sb_sort) {
        list_splice(&tmp, dispatch_queue);
        goto out;
    }

    /* Move inodes from one superblock together */
    while (!list_empty(&tmp)) {
        sb = wb_inode(tmp.prev)->i_sb;
        list_for_each_prev_safe(pos, node, &tmp) {
            inode = wb_inode(pos);
            if (inode->i_sb == sb)
                list_move(&inode->i_io_list, dispatch_queue);
        }
    }
out:
    return moved;
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
}

/*
 * requeue inode for re-scanning after bdi->b_io list is exhausted.
 */
static void requeue_io(struct inode *inode, struct bdi_writeback *wb)
{
    inode_io_list_move_locked(inode, wb, &wb->b_more_io);
}

static long writeback_chunk_size(struct bdi_writeback *wb,
                 struct wb_writeback_work *work)
{
    long pages;

    /*
     * WB_SYNC_ALL mode does livelock avoidance by syncing dirty
     * inodes/pages in one big loop. Setting wbc.nr_to_write=LONG_MAX
     * here avoids calling into writeback_inodes_wb() more than once.
     *
     * The intended call sequence for WB_SYNC_ALL writeback is:
     *
     *      wb_writeback()
     *          writeback_sb_inodes()       <== called only once
     *              write_cache_pages()     <== called once for each inode
     *                   (quickly) tag currently dirty pages
     *                   (maybe slowly) sync all tagged pages
     */
    if (work->sync_mode == WB_SYNC_ALL || work->tagged_writepages)
        pages = LONG_MAX;
    else {
        pages = min(wb->avg_write_bandwidth / 2,
                global_wb_domain.dirty_limit / DIRTY_SCOPE);
        pages = min(pages, work->nr_pages);
        pages = round_down(pages + MIN_WRITEBACK_PAGES,
                   MIN_WRITEBACK_PAGES);
    }

    printk("%s: ++++++++++++ Note: global_wb_domain.dirty_limit\n", __func__);
    return pages;
}

static int write_inode(struct inode *inode, struct writeback_control *wbc)
{
    int ret;

    panic("%s: ...\n", __func__);
    if (inode->i_sb->s_op->write_inode && !is_bad_inode(inode)) {
        //trace_writeback_write_inode_start(inode, wbc);
        ret = inode->i_sb->s_op->write_inode(inode, wbc);
        //trace_writeback_write_inode(inode, wbc);
        return ret;
    }
    return 0;
}

/*
 * Write out an inode and its dirty pages. Do not update the writeback list
 * linkage. That is left to the caller. The caller is also responsible for
 * setting I_SYNC flag and calling inode_sync_complete() to clear it.
 */
static int
__writeback_single_inode(struct inode *inode, struct writeback_control *wbc)
{
    struct address_space *mapping = inode->i_mapping;
    long nr_to_write = wbc->nr_to_write;
    unsigned dirty;
    int ret;

    WARN_ON(!(inode->i_state & I_SYNC));

    //trace_writeback_single_inode_start(inode, wbc, nr_to_write);

    ret = do_writepages(mapping, wbc);

    /*
     * Make sure to wait on the data before writing out the metadata.
     * This is important for filesystems that modify metadata on data
     * I/O completion. We don't do it for sync(2) writeback because it has a
     * separate, external IO completion path and ->sync_fs for guaranteeing
     * inode metadata is written back correctly.
     */
    if (wbc->sync_mode == WB_SYNC_ALL && !wbc->for_sync) {
        int err = filemap_fdatawait(mapping);
        if (ret == 0)
            ret = err;
    }

    /*
     * Some filesystems may redirty the inode during the writeback
     * due to delalloc, clear dirty metadata flags right before
     * write_inode()
     */
    spin_lock(&inode->i_lock);

    dirty = inode->i_state & I_DIRTY;
    if ((inode->i_state & I_DIRTY_TIME) &&
        ((dirty & I_DIRTY_INODE) ||
         wbc->sync_mode == WB_SYNC_ALL || wbc->for_sync ||
         time_after(jiffies, inode->dirtied_time_when +
            dirtytime_expire_interval * HZ))) {
        dirty |= I_DIRTY_TIME;
        //trace_writeback_lazytime(inode);
    }
    inode->i_state &= ~dirty;

    /*
     * Paired with smp_mb() in __mark_inode_dirty().  This allows
     * __mark_inode_dirty() to test i_state without grabbing i_lock -
     * either they see the I_DIRTY bits cleared or we see the dirtied
     * inode.
     *
     * I_DIRTY_PAGES is always cleared together above even if @mapping
     * still has dirty pages.  The flag is reinstated after smp_mb() if
     * necessary.  This guarantees that either __mark_inode_dirty()
     * sees clear I_DIRTY_PAGES or we see PAGECACHE_TAG_DIRTY.
     */
    smp_mb();

    if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
        inode->i_state |= I_DIRTY_PAGES;

    spin_unlock(&inode->i_lock);

    printk("%s: ...\n", __func__);
    if (dirty & I_DIRTY_TIME)
        mark_inode_dirty_sync(inode);
    /* Don't write the inode if only I_DIRTY_PAGES was set */
    if (dirty & ~I_DIRTY_PAGES) {
        int err = write_inode(inode, wbc);
        if (ret == 0)
            ret = err;
    }
    //trace_writeback_single_inode(inode, wbc, nr_to_write);
    return ret;
}

/**
 * inode_io_list_del_locked - remove an inode from its bdi_writeback IO list
 * @inode: inode to be removed
 * @wb: bdi_writeback @inode is being removed from
 *
 * Remove @inode which may be on one of @wb->b_{dirty|io|more_io} lists and
 * clear %WB_has_dirty_io if all are empty afterwards.
 */
static void inode_io_list_del_locked(struct inode *inode,
                     struct bdi_writeback *wb)
{
    assert_spin_locked(&wb->list_lock);
    assert_spin_locked(&inode->i_lock);

    inode->i_state &= ~I_SYNC_QUEUED;
    list_del_init(&inode->i_io_list);
    wb_io_lists_depopulated(wb);
}

/*
 * Find proper writeback list for the inode depending on its current state and
 * possibly also change of its state while we were doing writeback.  Here we
 * handle things such as livelock prevention or fairness of writeback among
 * inodes. This function can be called only by flusher thread - noone else
 * processes all inodes in writeback lists and requeueing inodes behind flusher
 * thread's back can have unexpected consequences.
 */
static void requeue_inode(struct inode *inode, struct bdi_writeback *wb,
              struct writeback_control *wbc)
{
    if (inode->i_state & I_FREEING)
        return;

    /*
     * Sync livelock prevention. Each inode is tagged and synced in one
     * shot. If still dirty, it will be redirty_tail()'ed below.  Update
     * the dirty time to prevent enqueue and sync it again.
     */
    if ((inode->i_state & I_DIRTY) &&
        (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages))
        inode->dirtied_when = jiffies;

    if (wbc->pages_skipped) {
        /*
         * writeback is not making progress due to locked
         * buffers. Skip this inode for now.
         */
        redirty_tail_locked(inode, wb);
        return;
    }

    if (mapping_tagged(inode->i_mapping, PAGECACHE_TAG_DIRTY)) {
        /*
         * We didn't write back all the pages.  nfs_writepages()
         * sometimes bales out without doing anything.
         */
        if (wbc->nr_to_write <= 0) {
            /* Slice used up. Queue for next turn. */
            requeue_io(inode, wb);
        } else {
            /*
             * Writeback blocked by something other than
             * congestion. Delay the inode for some time to
             * avoid spinning on the CPU (100% iowait)
             * retrying writeback of the dirty page/inode
             * that cannot be performed immediately.
             */
            redirty_tail_locked(inode, wb);
        }
    } else if (inode->i_state & I_DIRTY) {
        /*
         * Filesystems can dirty the inode during writeback operations,
         * such as delayed allocation during submission or metadata
         * updates after data IO completion.
         */
        redirty_tail_locked(inode, wb);
    } else if (inode->i_state & I_DIRTY_TIME) {
        inode->dirtied_when = jiffies;
        inode_io_list_move_locked(inode, wb, &wb->b_dirty_time);
        inode->i_state &= ~I_SYNC_QUEUED;
    } else {
        /* The inode is clean. Remove from writeback lists. */
        inode_io_list_del_locked(inode, wb);
    }
}

static void inode_sync_complete(struct inode *inode)
{
    inode->i_state &= ~I_SYNC;
    /* If inode is clean an unused, put it into LRU now... */
    inode_add_lru(inode);
    /* Waiters must see I_SYNC cleared before being woken up */
    smp_mb();
    wake_up_bit(&inode->i_state, __I_SYNC);
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
    struct writeback_control wbc = {
        .sync_mode      = work->sync_mode,
        .tagged_writepages  = work->tagged_writepages,
        .for_kupdate        = work->for_kupdate,
        .for_background     = work->for_background,
        .for_sync       = work->for_sync,
        .range_cyclic       = work->range_cyclic,
        .range_start        = 0,
        .range_end      = LLONG_MAX,
    };
    unsigned long start_time = jiffies;
    long write_chunk;
    long wrote = 0;  /* count both pages and inodes */

    while (!list_empty(&wb->b_io)) {
        struct inode *inode = wb_inode(wb->b_io.prev);
        struct bdi_writeback *tmp_wb;

        if (inode->i_sb != sb) {
            if (work->sb) {
                /*
                 * We only want to write back data for this
                 * superblock, move all inodes not belonging
                 * to it back onto the dirty list.
                 */
                redirty_tail(inode, wb);
                continue;
            }

            /*
             * The inode belongs to a different superblock.
             * Bounce back to the caller to unpin this and
             * pin the next superblock.
             */
            break;
        }

        /*
         * Don't bother with new inodes or inodes being freed, first
         * kind does not need periodic writeout yet, and for the latter
         * kind writeout is handled by the freer.
         */
        spin_lock(&inode->i_lock);
        if (inode->i_state & (I_NEW | I_FREEING | I_WILL_FREE)) {
            redirty_tail_locked(inode, wb);
            spin_unlock(&inode->i_lock);
            continue;
        }
        if ((inode->i_state & I_SYNC) && wbc.sync_mode != WB_SYNC_ALL) {
            /*
             * If this inode is locked for writeback and we are not
             * doing writeback-for-data-integrity, move it to
             * b_more_io so that writeback can proceed with the
             * other inodes on s_io.
             *
             * We'll have another go at writing back this inode
             * when we completed a full scan of b_io.
             */
            spin_unlock(&inode->i_lock);
            requeue_io(inode, wb);
            //trace_writeback_sb_inodes_requeue(inode);
            continue;
        }
        spin_unlock(&wb->list_lock);

        /*
         * We already requeued the inode if it had I_SYNC set and we
         * are doing WB_SYNC_NONE writeback. So this catches only the
         * WB_SYNC_ALL case.
         */
        if (inode->i_state & I_SYNC) {
            /* Wait for I_SYNC. This function drops i_lock... */
            inode_sleep_on_writeback(inode);
            /* Inode may be gone, start again */
            spin_lock(&wb->list_lock);
            continue;
        }
        inode->i_state |= I_SYNC;
        wbc_attach_and_unlock_inode(&wbc, inode);

        write_chunk = writeback_chunk_size(wb, work);
        wbc.nr_to_write = write_chunk;
        wbc.pages_skipped = 0;

        /*
         * We use I_SYNC to pin the inode in memory. While it is set
         * evict_inode() will wait so the inode cannot be freed.
         */
        __writeback_single_inode(inode, &wbc);

        wbc_detach_inode(&wbc);
        work->nr_pages -= write_chunk - wbc.nr_to_write;
        wrote += write_chunk - wbc.nr_to_write;

        if (need_resched()) {
            /*
             * We're trying to balance between building up a nice
             * long list of IOs to improve our merge rate, and
             * getting those IOs out quickly for anyone throttling
             * in balance_dirty_pages().  cond_resched() doesn't
             * unplug, so get our IOs out the door before we
             * give up the CPU.
             */
            blk_flush_plug(current);
            cond_resched();
        }

        /*
         * Requeue @inode if still dirty.  Be careful as @inode may
         * have been switched to another wb in the meantime.
         */
        tmp_wb = inode_to_wb_and_lock_list(inode);
        spin_lock(&inode->i_lock);
        if (!(inode->i_state & I_DIRTY_ALL))
            wrote++;
        requeue_inode(inode, tmp_wb, &wbc);
        inode_sync_complete(inode);
        spin_unlock(&inode->i_lock);

        if (unlikely(tmp_wb != wb)) {
            spin_unlock(&tmp_wb->list_lock);
            spin_lock(&wb->list_lock);
        }

        /*
         * bail out to wb_writeback() often enough to check
         * background threshold and other termination conditions.
         */
        if (wrote) {
            if (time_is_before_jiffies(start_time + HZ / 10UL))
                break;
            if (work->nr_pages <= 0)
                break;
        }
    }
    return wrote;
}

static long __writeback_inodes_wb(struct bdi_writeback *wb,
                  struct wb_writeback_work *work)
{
    unsigned long start_time = jiffies;
    long wrote = 0;

    printk("%s: ...\n", __func__);
    while (!list_empty(&wb->b_io)) {
        struct inode *inode = wb_inode(wb->b_io.prev);
        struct super_block *sb = inode->i_sb;

#if 0
        if (!trylock_super(sb)) {
            /*
             * trylock_super() may fail consistently due to
             * s_umount being grabbed by someone else. Don't use
             * requeue_io() to avoid busy retrying the inode/sb.
             */
            redirty_tail(inode, wb);
            continue;
        }
#endif
        wrote += writeback_sb_inodes(sb, wb, work);
        up_read(&sb->s_umount);

        /* refer to the same tests at the end of writeback_sb_inodes */
        if (wrote) {
            if (time_is_before_jiffies(start_time + HZ / 10UL))
                break;
            if (work->nr_pages <= 0)
                break;
        }
        printk("%s: in loop\n", __func__);
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
    printk("%s: stepN\n", __func__);
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
