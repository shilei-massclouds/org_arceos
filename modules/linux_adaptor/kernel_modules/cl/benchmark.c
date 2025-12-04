#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/blkdev.h>
#include <linux/syscalls.h>

#include "adaptor.h"

#define COUNT 1000

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
           size, count, (t1 - t0));

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

#if 0
static void trace_write_file(const char *fname)
{
    uint64_t t0, t1, t2, t3;

    struct file *f;
    printk("%s: open for trace_write .. .\n", __func__);
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
    create_test_file(path);
    trace_write_file(path);
#endif

    do_test(path, 64, COUNT);
    do_test(path, 128, COUNT);
    do_test(path, 1024, COUNT);
    do_test(path, 4096, COUNT);

    printk("Test ok!\n");
}


#if 0
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/blkdev.h>
#include <linux/syscalls.h>

#include "adaptor.h"
#include "cl_syscalls.h"

/* Default count 1000000 */
#define COUNT 1000

extern int cl_filp_flush(int fd);

static bool
_exists(const char *fname)
{
    struct stat buf;
    int err = cl_sys_newstat(fname, &buf);
    if (err < 0) {
        if (err == -ENOENT) {
            return false;
        } else {
            printk("stat err: %d\n", err);
            PANIC("get file stat err.");
        }
    }
    return true;
}

static void
create_test_file(const char *fname)
{
    int fd = cl_sys_open(fname, O_CREAT, S_IRUSR|S_IWUSR);
    if (fd < 0) {
        PANIC("bad file fd.");
    }
    printk("prepare test file '%s' fd '%d'.\n", fname, fd);

    if (cl_sys_close(fd)) {
        PANIC("close dir fd err.");
    }

    CL_ASSERT(_exists(fname), "No file after creating it.");
}

static void
remove_test_file(const char *fname)
{
    int err = cl_sys_unlink(fname);
    if (err < 0) {
        PANIC("remove file err.");
    }

    CL_ASSERT(!_exists(fname), "Found file after removing it.");
}

static void write_test_file(const char *fname, int size, int count)
{
    uint64_t t0, t1;

    int fd = cl_sys_open(fname, O_WRONLY, 0);
    if (fd < 0) {
        printk("open for write err '%d'.\n", fd);
        PANIC("bad dir fd.");
    }

    t0 = get_ticks();

    char wbuf[4096];
    for (int i = 0; i < count; i++) {
        if (count % 1000 == 0) {
            cl_sys_lseek(fd, 0, SEEK_SET);
        }

        int err = cl_sys_write(fd, wbuf, size);
        if (err < 0) {
            printk("write err: %d\n", err);
            PANIC("write file err.");
        }
        if (cl_filp_flush(fd) != 0) {
            PANIC("flush file err.");
        }
        if (cl_sys_fsync(fd) != 0) {
            PANIC("sync file err.");
        }
    }

    t1 = get_ticks();
    printk("WRITE [size=%d, count=%d]: ticks: %lu\n",
           size, count, (t1 - t0)/count);

    if (cl_sys_close(fd)) {
        PANIC("close dir fd err.");
    }
}

static void read_test_file(const char *fname, int size, int count)
{
    uint64_t t0, t1;

    int fd = cl_sys_open(fname, O_RDONLY, 0);
    if (fd < 0) {
        printk("open for write err '%d'.\n", fd);
        PANIC("bad dir fd.");
    }

    t0 = get_ticks();

    char rbuf[4096];
    for (int i = 0; i < count; i++) {
        if (count % 1000 == 0) {
            cl_sys_lseek(fd, 0, SEEK_SET);
        }

        int err = cl_sys_read(fd, rbuf, size);
        if (err < 0) {
            printk("read err: %d\n", err);
            PANIC("read file err.");
        }
    }

    t1 = get_ticks();
    printk("READ [size=%d, count=%d]: ticks: %lu\n",
           size, count, (t1 - t0)/count);

    if (cl_sys_close(fd)) {
        PANIC("close dir fd err.");
    }
}

static void do_test(const char *path, int size, int count)
{
    printk("Test [size=%d, count=%d] ...\n", size, count);
    create_test_file(path);

    write_test_file(path, size, count);
    read_test_file(path, size, count);

    remove_test_file(path);
    printk("Test [size=%d, count=%d] ok!\n", size, count);
}

void bench_ext4(void)
{
    char *path = "/bench_file";

    do_test(path, 64, COUNT);
    do_test(path, 128, COUNT);
    do_test(path, 1024, COUNT);
    do_test(path, 4096, COUNT);
}
#endif
