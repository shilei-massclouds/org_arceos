#include <linux/fs.h>
#include <linux/buffer_head.h>

#include "booter.h"

void mark_buffer_dirty(struct buffer_head *bh)
{
    log_error("%s: No impl.\n", __func__);
}

int sync_dirty_buffer(struct buffer_head *bh)
{
    printk("%s: blknr(%u) b_size(%u)\n",
           __func__, bh->b_blocknr, bh->b_size);

    log_error("%s: No impl.\n", __func__);
}

void __lock_buffer(struct buffer_head *bh)
{
    log_error("%s: No impl.\n", __func__);
}

void unlock_buffer(struct buffer_head *bh)
{
    clear_bit_unlock(BH_Lock, &bh->b_state);
    smp_mb__after_atomic();
    log_error("%s: No impl.\n", __func__);
    //wake_up_bit(&bh->b_state, BH_Lock);
}

/*
 * The generic ->writepage function for buffer-backed address_spaces
 */
int block_write_full_page(struct page *page,
                          get_block_t *get_block,
                          struct writeback_control *wbc)
{
    if (page == NULL || page->mapping == NULL) {
        booter_panic("bad page.");
    }

    struct inode *inode = page->mapping->host;
    if (inode == NULL) {
        booter_panic("bad inode.");
    }
    printk("%s: file len %u\n", __func__, inode->i_size);

    struct buffer_head bh_result;
    memset(&bh_result, 0, sizeof(struct buffer_head));
    bh_result.b_size = PAGE_SIZE;

    // Calculate iblock based on page->index
    sector_t iblock = 0;
    int ret = get_block(inode, iblock, &bh_result, 0);
    if (ret < 0) {
        booter_panic("ext2_get_block error!");
    }

    sector_t blknr = bh_result.b_blocknr * 8;
    printk("%s: blknr %u\n", __func__, blknr);

    if (cl_write_block(blknr, page_to_virt(page), PAGE_SIZE) < 0) {
        booter_panic("write block error!");
    }

    return 0;
}

void __breadahead_gfp(struct block_device *bdev, sector_t block, unsigned size,
              gfp_t gfp)
{
    return __bread_gfp(bdev, block, size, gfp);
}

struct buffer_head *
__getblk_gfp(struct block_device *bdev, sector_t block,
         unsigned size, gfp_t gfp)
{
    return __bread_gfp(bdev, block, size, gfp);
}

void __wait_on_buffer(struct buffer_head * bh)
{
    log_error("%s: impl it.\n", __func__);
    set_buffer_uptodate(bh);
}

/*
 * For a data-integrity writeout, we need to wait upon any in-progress I/O
 * and then start new I/O and then wait upon it.  The caller must have a ref on
 * the buffer_head.
 */
int __sync_dirty_buffer(struct buffer_head *bh, int op_flags)
{
    log_error("%s: impl it.\n", __func__);
    return 0;
}
