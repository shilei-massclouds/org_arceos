#include <linux/fs.h>
#include <linux/buffer_head.h>

#include "booter.h"

int mpage_readpage(struct page *page, get_block_t get_block)
{
    printk("%s: page %lx, get_block %lx\n", __func__, page, get_block);

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

    if (cl_read_block(blknr, page_to_virt(page), PAGE_SIZE) < 0) {
        booter_panic("read block error!");
    }

    return 0;
}
