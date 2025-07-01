#include <linux/string.h>
#include <linux/printk.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>

#include "booter.h"

//#define TEST_EXT2
#define TEST_EXT4

#ifdef TEST_EXT2
#include "ext2/ext2.h"
#endif

#ifdef TEST_EXT4
#include "ext4/ext4.h"
#endif

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

static void test_ext4(void)
{
    /*
     * Init Journal first.
     */
    cl_journal_init();

    /*
     * Ext4 mount and test
     */
    cl_ext4_fs_init();

    struct dentry *root = call_mount("ext4");
    if (root == NULL || root->d_inode == NULL) {
        booter_panic("ext4 mount error!");
    }

    struct inode *root_inode = root->d_inode;
    if (!S_ISDIR(root_inode->i_mode)) {
        booter_panic("ext4 root inode is NOT DIR!");
    }
    if (root_inode->i_sb == NULL) {
        booter_panic("No ext4 superblock!");
    }

    struct file root_dir;
    memset(&root_dir, 0, sizeof(root_dir));
    root_dir.f_inode = root_inode;

    // Lookup ino of 'ext4.txt'
    u64 t_ino = 0;
    lookup(&root_dir, "ext4.txt", &t_ino);
    printk("ext4.txt ino: %u\n", t_ino);

    struct inode *t_inode = ext4_iget(root_inode->i_sb, t_ino, 0);
    if (t_inode == NULL || t_inode->i_mapping == NULL) {
        booter_panic("bad inode.");
    }

    // Try to read content from 'ext4.txt'
    char rbuf[256];
    memset(rbuf, 0, sizeof(rbuf));
    loff_t pos = 0;
    int ret = cl_read(t_inode, rbuf, sizeof(rbuf), &pos);
    if (ret < 0) {
        booter_panic("ext4 read error!");
    }
    printk("Read 'ext4.txt': [%d]%s\n", ret, rbuf);

    booter_panic("Reach here!\n");
}

#ifdef TEST_EXT2
static void test_ext2(void)
{
    /*
     * Ext2 mount and test
     */
    cl_ext2_fs_init();

    struct dentry *root = call_mount("ext2");
    if (root == NULL || root->d_inode == NULL) {
        booter_panic("ext2 mount error!");
    }

    struct inode *root_inode = root->d_inode;
    if (!S_ISDIR(root_inode->i_mode)) {
        booter_panic("ext2 root inode is NOT DIR!");
    }
    if (root_inode->i_sb == NULL) {
        booter_panic("No ext2 superblock!");
    }

    struct file root_dir;
    memset(&root_dir, 0, sizeof(root_dir));
    root_dir.f_inode = root_inode;

    // Lookup ino of 'ext2.txt'
    u64 t_ino = 0;
    lookup(&root_dir, "ext2.txt", &t_ino);
    printk("ext2.txt ino: %u\n", t_ino);

    struct inode *t_inode = ext2_iget(root_inode->i_sb, t_ino);
    if (t_inode == NULL || t_inode->i_mapping == NULL) {
        booter_panic("bad inode.");
    }

    // Try to read content from 'ext2.txt'
    char rbuf[256];
    memset(rbuf, 0, sizeof(rbuf));
    loff_t pos = 0;
    int ret = cl_read(t_inode, rbuf, sizeof(rbuf), &pos);
    if (ret < 0) {
        booter_panic("ext2 read error!");
    }
    printk("Read 'ext2.txt': [%d]%s\n", ret, rbuf);

    char wbuf[] = "12345";
    pos = 0;
    ret = cl_write(t_inode, wbuf, sizeof(wbuf), &pos);
    if (ret < 0) {
        booter_panic("ext2 write error!");
    }

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
