#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/pagemap.h>

#include "booter.h"

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

    list_move(&inode->i_io_list, head);

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

    printk("%s: step1\n", __func__);
    //trace_writeback_mark_inode_dirty(inode, flags);

    /*
     * Don't do this for I_DIRTY_PAGES - that doesn't actually
     * dirty the inode itself
     */
    if (flags & (I_DIRTY_INODE | I_DIRTY_TIME)) {
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

            WARN(bdi_cap_writeback_dirty(wb->bdi) &&
                 !test_bit(WB_registered, &wb->state),
                 "bdi-%s not registered\n", bdi_dev_name(wb->bdi));

            inode->dirtied_when = jiffies;
            if (dirtytime)
                inode->dirtied_time_when = jiffies;

            if (inode->i_state & I_DIRTY)
                dirty_list = &wb->b_dirty;
            else
                dirty_list = &wb->b_dirty_time;

            wakeup_bdi = inode_io_list_move_locked(inode, wb,
                                   dirty_list);

            spin_unlock(&wb->list_lock);
            //trace_writeback_dirty_inode_enqueue(inode);

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
