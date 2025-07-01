#include <linux/fs.h>
#include <linux/writeback.h>

#include "booter.h"
//#include "ext2/ext2.h"

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

    ret = a_ops->writepage(page, &wbc);
    if (ret < 0) {
        booter_panic("write content error.");
    }

    if (inode->i_sb == NULL) {
        booter_panic("No superblock for inode.");
    }

    const struct super_operations *s_ops = inode->i_sb->s_op;
    if (s_ops == NULL) {
        booter_panic("bad superblock ops.");
    }

    // Note: Write inode when i_size changed.
    if (*pos + count > inode->i_size) {
        inode->i_size = *pos + count;
    }
    printk("%s: ino %u\n", __func__, inode->i_ino);

    memset(&wbc, 0, sizeof(wbc));
    wbc.sync_mode = WB_SYNC_ALL;
    ret = s_ops->write_inode(inode, &wbc);
    if (ret < 0) {
        booter_panic("write metadata error.");
    }

    *pos += count;
    return ret;
}
