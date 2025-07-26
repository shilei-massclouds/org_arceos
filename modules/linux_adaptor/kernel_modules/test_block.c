#include <linux/blkdev.h>
#include <linux/pagemap.h>

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

    struct folio *folio = folio_alloc(GFP_KERNEL, 0);
    if (folio == NULL) {
        PANIC("No page.");
    }
    folio->mapping = dev->bd_mapping;

    /* Read second block (index = 1 and size = PAGE_SIZE) */
    folio->index = 1;
    __folio_set_locked(folio);
    ret = a_ops->read_folio(NULL, folio);
    if (ret) {
        pr_err("Read block err: %d\n", ret);
        PANIC("Read error.");
    }
    ret = folio_wait_locked_killable(folio);
    if (ret) {
        PANIC("Wait unlocked error.");
    }
    if (!folio_test_uptodate(folio)) {
        PANIC("Not up_to_date.");
    }

    void *vaddr = page_to_virt(&folio->page);
    if (vaddr == NULL) {
        PANIC("Bad page.");
    }

    {
        unsigned int *dwords = (unsigned int *) vaddr;
        printk("Read: %08lx, %08lx, %08lx, %08lx\n",
               dwords[0], dwords[1], dwords[2], dwords[3]);
    }

    PANIC("Test block ok!");
}
