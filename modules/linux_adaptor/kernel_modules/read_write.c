#include <linux/fs.h>
#include <linux/writeback.h>

#include "booter.h"
#include "ext2/ext2.h"

int cl_read(struct inode *inode, void *buf, size_t count, loff_t *pos)
{
    int ret;
    if (inode == NULL || inode->i_mapping == NULL) {
        booter_panic("bad inode.");
    }

    const struct address_space_operations *a_ops = inode->i_mapping->a_ops;
    if (a_ops == NULL) {
        booter_panic("bad addrspace ops.");
    }

    void *page_buf = alloc_pages_exact(PAGE_SIZE, 0);
    struct page *page = virt_to_page(page_buf);
    page->mapping = inode->i_mapping;
    ret = a_ops->readpage(NULL, page);
    if (ret < 0) {
        return ret;
    }

    ret = min(count, (size_t)inode->i_size);
    memcpy(buf, page_buf, ret);
    return ret;
}

int cl_write(struct inode *inode, const void *buf, size_t count, loff_t *pos)
{
    int ret;
    printk("%s: count %d\n", __func__, count);
    if (inode == NULL || inode->i_mapping == NULL) {
        booter_panic("bad inode.");
    }

    const struct address_space_operations *a_ops = inode->i_mapping->a_ops;
    if (a_ops == NULL) {
        booter_panic("bad addrspace ops.");
    }

    void *page_buf = alloc_pages_exact(PAGE_SIZE, 0);
    memcpy(page_buf, buf, count);

    struct page *page = virt_to_page(page_buf);
    page->mapping = inode->i_mapping;

    struct writeback_control wbc;
    memset(&wbc, 0, sizeof(wbc));

    return a_ops->writepage(page, &wbc);
}
