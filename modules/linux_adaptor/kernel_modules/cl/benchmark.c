#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/blkdev.h>
#include <linux/syscalls.h>

#include "adaptor.h"
#include "ticks.h"

#define COUNT 1000

#define CSR_TIME		0xc01

extern int cl_filp_flush(struct file *filp, fl_owner_t id);

static void
create_test_file(const char *fname)
{
    struct file *f;
    f = filp_open(fname, O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
    if (IS_ERR(f)) {
        PANIC("bad file fd.");
    }

    printk("prepare test file '%s'.\n", fname);

    filp_close(f, 0);
}

static void
remove_test_file(const char *fname)
{
    /* Do nothing */
}

static void write_test_file(const char *fname, int size, int count)
{
    uint64_t t0, t1;

    struct file *f;
    printk("%s: open for write ..\n", __func__);
    f = filp_open(fname, O_WRONLY, 0);
    if (IS_ERR(f)) {
        PANIC("bad file for write.");
    }

    printk("%s: write ..\n", __func__);
    t0 = get_ticks();

    char wbuf[4096];
    loff_t pos = 0;
    for (int i = 0; i < count; i++) {
        if (count % 1000 == 0) {
            pos = 0;
        }

        int err = kernel_write(f, wbuf, size, &pos);
        if (err < 0) {
            printk("write err: %d\n", err);
            PANIC("write file err.");
        }
        if (cl_filp_flush(f, 0) != 0) {
            PANIC("flush file err.");
        }
        if (vfs_fsync(f, 0) != 0) {
            PANIC("sync file err.");
        }
    }

    t1 = get_ticks();
    printk("WRITE [size=%d, count=%d]: ticks: %llu\n",
           size, count, (t1 - t0)/count);

    if (filp_close(f, 0)) {
        PANIC("close dir fd err.");
    }

    printk("%s: close for write!\n", __func__);
}

static void read_test_file(const char *fname, int size, int count)
{
    uint64_t t0, t1;

    struct file *f;
    f = filp_open(fname, O_RDONLY, 0);
    if (IS_ERR(f)) {
        PANIC("bad file for read.");
    }

    printk("%s: read ..\n", __func__);
    t0 = get_ticks();

    char rbuf[4096];
    loff_t pos = 0;
    for (int i = 0; i < count; i++) {
        if (count % 1000 == 0) {
            pos = 0;
        }

        int err = kernel_read(f, rbuf, size, &pos);
        if (err < 0) {
            printk("read err: %d\n", err);
            PANIC("read file err.");
        }
    }

    t1 = get_ticks();
    printk("READ [size=%d, count=%d]: ticks: %llu\n",
           size, count, (t1 - t0)/count);

    if (filp_close(f, 0)) {
        PANIC("close dir fd err.");
    }
}

static void do_test(const char *path, int size, int count)
{
    create_test_file(path);

    write_test_file(path, size, count);
    read_test_file(path, size, count);

    remove_test_file(path);
}

#if 1
static void single_write_file(const char *fname)
{
    uint64_t t0, t1, t2, t3;

    struct file *f;
    printk("%s: open for single_write .. .\n", __func__);
    f = filp_open(fname, O_WRONLY, 0);
    if (IS_ERR(f)) {
        PANIC("bad file for write.");
    }

    printk("%s: write ..\n", __func__);

    char wbuf[4096];
    loff_t pos = 0;

    t0 = get_ticks();

    int err = kernel_write(f, wbuf, 64, &pos);
    if (err < 0) {
        printk("write err: %d\n", err);
        PANIC("write file err.");
    }

    t1 = get_ticks();

    if (cl_filp_flush(f, 0) != 0) {
        PANIC("flush file err.");
    }

    t2 = get_ticks();

    if (vfs_fsync(f, 0) != 0) {
        PANIC("sync file err.");
    }

    t3 = get_ticks();

    printk("%s: %llu, %llu, %llu\n", __func__, t1-t0, t2-t1, t3-t2);

    if (filp_close(f, 0)) {
        PANIC("close dir fd err.");
    }

    printk("%s: close for write!\n", __func__);
}
#endif

void bench_ext4(void)
{
    char *path = "/bench_file";

#if 0
    /* Single write */
    create_test_file(path);
    single_write_file(path);

    read_test_file(path, 64, 1);
#endif

#if 1
    do_test(path, 64, COUNT);
    do_test(path, 128, COUNT);
    do_test(path, 256, COUNT);
    do_test(path, 512, COUNT);
    do_test(path, 1024, COUNT);
    do_test(path, 4096, COUNT);
#endif

    unsigned long size = 10*SZ_1M;
    int order = get_order(size);
    printk("size = %lx order = %u\n", size, order);
    void *src = __get_free_pages(GFP_KERNEL, order);
    void *dst = __get_free_pages(GFP_KERNEL, order);

    uint64_t t0, t1;

    t0 = get_ticks();
    memcpy(dst, src, size);
    t1 = get_ticks();

    printk("memcpy ticks: %llu\n", t1 - t0);

    printk("Test ok!\n");
}
