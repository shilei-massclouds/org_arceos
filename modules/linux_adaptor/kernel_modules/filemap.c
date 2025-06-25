#include <linux/fs.h>
#include <linux/buffer_head.h>

#include "ext2/ext2.h"
#include "booter.h"

struct page *read_cache_page(struct address_space *mapping,
                pgoff_t index,
                int (*filler)(void *, struct page *),
                void *data)
{
    printk("%s: mapping (%lx) index(%d) data(%x)\n",
                 __func__, mapping, index, data);

    struct buffer_head bh_result;
    memset(&bh_result, 0, sizeof(struct buffer_head));
    bh_result.b_size = 4096;

    sector_t iblock = 0;
    int ret = ext2_get_block(mapping->host, iblock, &bh_result, 0);
    if (ret < 0) {
        booter_panic("ext2_get_block error!");
    }

    // 4096 -> 512
    sector_t blknr = bh_result.b_blocknr * 8;
    log_error("%s: blknr(%u -> %u)\n",
              __func__, bh_result.b_blocknr, blknr);

    void *buf = alloc_pages_exact(PAGE_SIZE, 0);
    if (cl_read_block(blknr, buf, PAGE_SIZE) < 0) {
        booter_panic("read block error!");
    }

    struct page *page = virt_to_page(buf);
    init_page_count(page);
    page->mapping = mapping;
    page->index = index;
    return page;
}
