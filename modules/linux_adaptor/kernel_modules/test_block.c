#include <linux/blkdev.h>

#include "adaptor.h"

void test_block(void)
{
    int ret;
    const struct address_space_operations *a_ops;
    struct block_device *dev;

    dev = blkdev_get_no_open(MKDEV(0xFE, 0x00));
    if (dev == NULL || dev->bd_mapping == NULL) {
        PANIC("No block device!");
    }

    a_ops = dev->bd_mapping->a_ops;
    if (a_ops == NULL) {
        PANIC("No bdev page cache ops!");
    }

    /*
     * Read block tests
     */
    if (a_ops->read_folio == NULL) {
        PANIC("No 'read_folio'.");
    }

    struct page *page = alloc_page(GFP_KERNEL);
    if (page == NULL) {
        PANIC("No page.");
    }
    page->mapping = dev->bd_mapping;

    /* Read first block (PAGE_SIZE) */
    page->index = 0;
    __folio_set_locked(page);
    ret = a_ops->read_folio(NULL, page);
    if (ret) {
        pr_err("Read block err: %d\n", ret);
    }

    PANIC("Test block ok!");
}
