#include "booter.h"
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/dcache.h>
#include <linux/fs.h>

#define TEST_EXT2

extern int cl_irq_init(void);
extern int cl_enable_irq(void);

extern void cl_virtio_init();
extern void cl_virtio_mmio_init();
extern void cl_virtio_blk_init();
extern int cl_ext2_fs_init(void);

/* Stuff needed by irq-sifive-plic */
unsigned long boot_cpu_hartid;

static int test_read_blocks();
static int test_write_blocks();
extern int clinux_test_block_driver(void);
extern struct dentry *call_ext2_mount(void);

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
    /*
     * Ext2 mount and test
     */
    cl_ext2_fs_init();

    struct dentry *root = call_ext2_mount();
    if (root == NULL || root->d_inode == NULL) {
        booter_panic("ext2 mount error!");
    }

    struct inode *root_inode = root->d_inode;
    if (!S_ISDIR(root_inode->i_mode)) {
        booter_panic("ext2 root inode is NOT DIR!");
    }

    const struct file_operations *dop = root_inode->i_fop;
    if (dop == NULL) {
        booter_panic("ext2 root inode has no fop!");
    }
    printk("root.inode (%lx) dop(%lx)\n", root_inode, dop);
    printk("root.inode iterate_shared(%lx)\n", dop->iterate_shared);

    struct file root_dir;
    memset(&root_dir, 0, sizeof(root_dir));
    root_dir.f_inode = root_inode;

    struct dir_context ctx;
    memset(&ctx, 0, sizeof(ctx));

    if ((*dop->iterate_shared)(&root_dir, &ctx) != 0) {
        booter_panic("ext2 root iterate error!");
    }

    booter_panic("Reach here!\n");
#endif
    return 0;
}

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
