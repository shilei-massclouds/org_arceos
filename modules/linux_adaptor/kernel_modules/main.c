#include <linux/string.h>
#include <linux/printk.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>

#include "booter.h"

//#define TEST_EXT2
#define TEST_EXT4

extern int cl_irq_init(void);
extern int cl_enable_irq(void);

extern void cl_virtio_init();
extern void cl_virtio_mmio_init();
extern void cl_virtio_blk_init();

extern int cl_ext2_fs_init(void);
extern int cl_ext4_fs_init(void);
extern int cl_journal_init(void);

extern int cl_read(struct inode *inode, void *buf, size_t count, loff_t *pos);
extern int cl_write(struct inode *inode, const void *buf, size_t count, loff_t *pos);

/* Stuff needed by irq-sifive-plic */
unsigned long boot_cpu_hartid;

static int test_read_blocks();
static int test_write_blocks();
extern int clinux_test_block_driver(void);
extern struct dentry *call_mount(const char *name);
extern int lookup(struct file *dir, const char *target, u64 *ret_ino);

extern ssize_t new_sync_read(struct file *filp, char *buf, size_t len, loff_t *ppos);
extern ssize_t new_sync_write(struct file *filp, const char *buf, size_t len, loff_t *ppos);

static void test_ext2(void);
static void test_ext4(void);

int clinux_init()
{
    printk("cLinux base is starting ...\n");

    cl_irq_init();

    cl_virtio_init();
    cl_virtio_mmio_init();
    cl_virtio_blk_init();

    cl_enable_irq();

    clinux_test_block_driver();

#ifdef TEST_EXT2
    test_ext2();
#endif

#ifdef TEST_EXT4
    test_ext4();
#endif
    return 0;
}

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

    loff_t pos = 0;
    char wbuf[] = "bcd";

    ret = new_sync_write(&file, wbuf, sizeof(wbuf), &pos);
    printk("Write '%s': ret [%d]\n", fs_name, ret);
}

static void test_basic(const char *fs_name, const char *fname)
{
    struct dentry *root = call_mount(fs_name);
    if (root == NULL || root->d_inode == NULL) {
        booter_panic("fs mount error!");
    }

    struct inode *root_inode = root->d_inode;
    if (!S_ISDIR(root_inode->i_mode)) {
        booter_panic("fs root inode is NOT DIR!");
    }
    if (root_inode->i_sb == NULL) {
        booter_panic("No fs superblock!");
    }

    struct file root_dir;
    memset(&root_dir, 0, sizeof(root_dir));
    root_dir.f_inode = root_inode;

    // Lookup inode of filesystem.
    unsigned int lookup_flags = 0;
    struct dentry target;
    memset(&target, 0, sizeof(struct dentry));
    target.d_name.name = fname;
    target.d_name.len = strlen(target.d_name.name);
    target.d_name.hash = 0;

    root_inode->i_op->lookup(root_inode, &target, lookup_flags);

    struct inode *t_inode = target.d_inode;
    if (t_inode == NULL || t_inode->i_mapping == NULL) {
        booter_panic("bad inode.");
    }

    test_read(t_inode, fs_name);

    test_write(t_inode, fs_name);

#ifdef TEST_EXT2
    char wbuf[] = "12345";
    pos = 0;
    ret = cl_write(t_inode, wbuf, sizeof(wbuf), &pos);
    if (ret < 0) {
        booter_panic("ext2 write error!");
    }
#endif
}

#ifdef TEST_EXT4
static void test_ext4(void)
{
    radix_tree_init();
    buffer_init();

    /*
     * Init Journal first.
     */
    cl_journal_init();

    /*
     * Ext4 mount and test
     */
    cl_ext4_fs_init();

    /*
     * Test read & write.
     */
    test_basic("ext4", "ext4.txt");

    booter_panic("Reach here!\n");
}
#endif

#ifdef TEST_EXT2
static void test_ext2(void)
{
    /*
     * Ext2 mount and test
     */
    cl_ext2_fs_init();

    /*
     * Test read & write.
     */
    test_basic("ext2", "ext2.txt");

    booter_panic("Reach here!\n");
}
#endif

int clinux_test_block_driver(void)
{
#if 0
    test_read_blocks();
    booter_panic("Reach here!\n");
#endif

#if 0
    test_write_blocks();
    booter_panic("Reach here!\n");
#endif
    return 0;
}

/* Utilities for testing */
static int read_a_block(int blk_nr)
{
    char buf[16];
    memset(buf, 0, sizeof(buf));
    cl_read_block(blk_nr, buf, sizeof(buf));
    printk("after cl_read_block!\n");
    /*
    if (!buf[0] || !buf[1] || !buf[2] || !buf[3]) {
        booter_panic("Read block error!\n");
    }
    */

    printk("\n=============\n");
    printk("Read Block[%d]: %x, %x, %x, %x\n",
           blk_nr, buf[0], buf[1], buf[2], buf[3]);
    printk("=============\n\n");
    return 0;
}

/* Test for reading block */
static int test_read_blocks()
{
    read_a_block(0);
    read_a_block(1);
}

static int write_a_block(int blk_nr)
{
    read_a_block(blk_nr);
    read_a_block(blk_nr+1);

    char wbuf[512];
    memset(wbuf, 0xAB, sizeof(wbuf));
    cl_write_block(blk_nr, wbuf, sizeof(wbuf));

    read_a_block(blk_nr);
    read_a_block(blk_nr+1);
}

/* Test for writing block */
static int test_write_blocks()
{
    write_a_block(0);
}
