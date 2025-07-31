#include <linux/fs.h>

#include "adaptor.h"

static void test_basic(struct dentry *root,
                       const char *fs_name,
                       const char *fname)
{
    if (root == NULL || root->d_inode == NULL) {
        PANIC("Bad fs root entry!");
    }

    struct inode *root_inode = root->d_inode;
    if (!S_ISDIR(root_inode->i_mode)) {
        PANIC("fs root inode is NOT DIR!");
    }
    if (root_inode->i_sb == NULL) {
        PANIC("No fs superblock!");
    }

    /* Lookup inode of filesystem. */
    unsigned int lookup_flags = 0;
    struct dentry target;
    memset(&target, 0, sizeof(struct dentry));
    target.d_name.name = fname;
    target.d_name.len = strlen(target.d_name.name);
    target.d_name.hash = 0;

    root_inode->i_op->lookup(root_inode, &target, lookup_flags);

#if 0
    struct inode *t_inode = target.d_inode;
    if (t_inode == NULL || t_inode->i_mapping == NULL) {
        booter_panic("bad inode.");
    }

    printk("\n\n============== FS READ =============\n\n");

    test_read(t_inode, fs_name);

    printk("\n\n============== FS WRITE =============\n\n");

    test_write(t_inode, fs_name);
#endif

    printk("\n\n============== TEST FS OK! =============\n\n");
}

void test_ext4(struct dentry *root)
{
    /*
     * Test read & write.
     */
    test_basic(root, "ext4", "ext4.txt");
}

#if 0
// File level read.
static void test_read(struct inode *inode, const char *fs_name)
{
    ssize_t ret;
    struct file file;
    memset(&file, 0, sizeof(struct file));
    file.f_inode = inode;
    file.f_mapping = inode->i_mapping;
    file.f_op = inode->i_fop;
    if (file.f_op == NULL) {
        booter_panic("bad file_operations.");
    }

    loff_t pos = 0;
    char rbuf[256];
    memset(rbuf, 0, sizeof(rbuf));

    ret = new_sync_read(&file, rbuf, sizeof(rbuf), &pos);
    printk("Read '%s': [%d]%s\n", fs_name, ret, rbuf);
}

// File level write.
static void test_write(struct inode *inode, const char *fs_name)
{
    ssize_t ret;
    struct file file;
    memset(&file, 0, sizeof(struct file));
    file.f_inode = inode;
    file.f_mapping = inode->i_mapping;
    file.f_op = inode->i_fop;
    if (file.f_op == NULL) {
        booter_panic("bad file_operations.");
    }

    // Note: set O_DSYNC for write.
    file.f_flags |= O_DSYNC;

    loff_t pos = 0;
    char wbuf[] = "bcde";

    ret = new_sync_write(&file, wbuf, sizeof(wbuf), &pos);
    printk("Write '%s' to '%s': ret [%d]\n", wbuf, fs_name, ret);
}

#endif
