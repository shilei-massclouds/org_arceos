#include <linux/blkdev.h>
#include <linux/pagemap.h>
#include <linux/reboot.h>
#include <linux/buffer_head.h>

#include "adaptor.h"

extern dev_t ROOT_DEV;

static const struct address_space *
prepare_block_dev(void)
{
    struct block_device *dev;

    dev = blkdev_get_no_open(ROOT_DEV);
    if (dev == NULL || dev->bd_mapping == NULL) {
        PANIC("No block device!");
    }
    return dev->bd_mapping;
}

static void test_read(const struct address_space *aspace, int index)
{
    int ret;
    const struct address_space_operations *a_ops;

    if (aspace == NULL || aspace->a_ops == NULL) {
        PANIC("No bdev aspace!");
    }
    a_ops = aspace->a_ops;

    if (a_ops->read_folio == NULL) {
        PANIC("No 'read_folio'.");
    }

    struct folio *folio = folio_alloc(GFP_KERNEL, 0);
    if (folio == NULL) {
        PANIC("No page.");
    }
    if (folio_buffers(folio) != NULL) {
        PANIC("Bad folio with buffers.");
    }
    folio->mapping = (struct address_space *)aspace;

    folio->index = index;
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

    /* Verify block content. */
    {
        unsigned int *dwords = (unsigned int *) vaddr;
        printk("Read: %08lx, %08lx, %08lx, %08lx\n",
               dwords[0], dwords[1], dwords[2], dwords[3]);
    }

    __free_page(folio_page(folio, 0));

    //machine_power_off();
    PANIC("Test block ok!");
}

void test_block(void)
{
    const struct address_space *aspace;
    aspace = prepare_block_dev();

    /* Read second block (index = 1 and size = PAGE_SIZE) */
    test_read(aspace, 1);
}
