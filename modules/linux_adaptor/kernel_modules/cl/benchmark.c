#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/blkdev.h>
#include <linux/syscalls.h>

#include "adaptor.h"
#include "cl_syscalls.h"

static uint64_t get_ticks(void)
{
    return csr_read(CSR_CYCLE);
}

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
        int err = cl_sys_write(fd, wbuf, size);
        if (err < 0) {
            printk("write err: %d\n", err);
            PANIC("write file err.");
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
    create_test_file(path);

    write_test_file(path, size, count);
    read_test_file(path, size, count);

    remove_test_file(path);
}

void bench_ext4(void)
{
    char *path = "/bench_file";

    do_test(path, 64, 1000);
    do_test(path, 128, 1000);
    do_test(path, 1024, 1000);
    do_test(path, 4096, 1000);
}
