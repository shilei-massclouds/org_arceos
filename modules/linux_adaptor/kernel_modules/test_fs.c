#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/blkdev.h>
#include <linux/syscalls.h>

#include "adaptor.h"
#include "cl_syscalls.h"

/*
 * Utilities
 */

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

/*
 * Testcases
 */

#define _BUF_LEN 512
#define _DIR_BUF_LEN 512

static void
test_getdents64(void)
{
    printk("\n============== getdents64 ... =============\n\n");

    int fd = cl_sys_open("/", O_DIRECTORY, 0);
    if (fd < 0) {
        PANIC("bad dir fd.");
    }
    printk("%s: open dir fd '%d'\n", __func__, fd);

    char buf[_DIR_BUF_LEN];
    struct linux_dirent64 *dirent = (struct linux_dirent64 *) buf;
    int count = cl_sys_getdents64(fd, dirent, sizeof(buf));
    if (count <= 0) {
        printk("read dir err %d.\n", count);
        PANIC("read dir err.");
    }

    int pos = 0;
    while (pos < count) {
        struct linux_dirent64 *dirent = (struct linux_dirent64 *) (buf + pos);
        printk("[%lu] %s type(%u) len(%u)\n",
               dirent->d_ino, dirent->d_name, dirent->d_type, dirent->d_reclen);
        pos += dirent->d_reclen;
    }

    if (cl_sys_close(fd)) {
        PANIC("close dir fd err.");
    }

    printk("\n============== getdents64 ok! =============\n\n");
}

static void
test_file_create(const char *fname)
{
    printk("\n============== file create ... =============\n\n");

    int fd = cl_sys_open(fname, O_CREAT, S_IRUSR|S_IWUSR);
    if (fd < 0) {
        PANIC("bad file fd.");
    }
    printk("create file '%s' fd '%d'.\n", fname, fd);

    if (cl_sys_close(fd)) {
        PANIC("close dir fd err.");
    }

    CL_ASSERT(_exists(fname), "No file after creating it.");

    printk("\n============== file create ok! =============\n\n");
}

static void
test_dir_create(const char *dname)
{
    printk("\n============== dir create ... =============\n\n");

    CL_ASSERT(!_exists(dname), "dir already exists.");

    printk("create dir '%s'.\n", dname);
    int err = cl_sys_mkdir(dname, 0700);
    if (err) {
        printk("create dir '%s' error '%d'.\n", dname, err);
        PANIC("create dir err.");
    }

    CL_ASSERT(_exists(dname), "No dir after creating it.");

    printk("\n============== dir create ok! =============\n\n");
}

static void
test_dir_remove(const char *dname)
{
    printk("\n============== dir remove ... =============\n\n");

    CL_ASSERT(_exists(dname), "No dir.");

    printk("remove dir '%s'.\n", dname);
    int err = cl_sys_rmdir(dname);
    if (err) {
        printk("remove dir '%s' error '%d'.\n", dname, err);
        PANIC("remove dir err.");
    }

    CL_ASSERT(!_exists(dname), "remove dir error.");

    printk("\n============== dir remove ok! =============\n\n");
}

static void
test_file_remove(const char *fname)
{
    printk("\n============== file remove ... =============\n\n");

    int err = cl_sys_unlink(fname);
    if (err < 0) {
        PANIC("remove file err.");
    }

    CL_ASSERT(!_exists(fname), "Found file after removing it.");

    printk("\n============== file remove ok! =============\n\n");
}

static void
test_stat(const char *path)
{
    printk("\n============== stat ... =============\n\n");

    struct stat buf;
    int err = cl_sys_newstat(path, &buf);
    if (err < 0) {
        if (err == -ENOENT) {
            PANIC("No such item.\n");
        } else {
            printk("stat err: %d\n", err);
            PANIC("get stat err.");
        }
    } else {
        printk("[%s] ino: %lu, mode: %u, size: %ld\n",
               path, buf.st_ino, buf.st_mode, buf.st_size);
        if (S_ISREG(buf.st_mode)) {
            printk("It is a FILE.\n");
        } else if (S_ISDIR(buf.st_mode)) {
            printk("It is a DIR.\n");
        } else {
            printk("It is other types.\n");
        }
    }

    printk("\n============== stat ok! =============\n\n");
}

static int
test_file_read(const char *fname, char *buf, size_t len, off_t offset)
{
    printk("\n============== file read ... =============\n\n");

    int fd = cl_sys_open(fname, O_RDONLY, 0);
    if (fd < 0) {
        printk("open for read err '%d'.\n", fd);
        PANIC("bad dir fd.");
    }
    printk("%s: open file '%s' fd '%d'\n", __func__, fname, fd);

    int pos = cl_sys_lseek(fd, offset, SEEK_SET);
    CL_ASSERT(pos == offset, "seek error.");

    int err = cl_sys_read(fd, buf, len);
    if (err < 0) {
        printk("read err: %d\n", err);
        PANIC("read file err.");
    }

    if (err > 0) {
        printk("read file: [%d] '%s'\n", err, buf);
    }

    if (cl_sys_close(fd)) {
        PANIC("close dir fd err.");
    }

    printk("\n============== file read ok! =============\n\n");
    return err;
}

static void
test_file_write(const char *fname, const char *buf, size_t len, off_t offset)
{
    printk("\n============== file write ... =============\n\n");

    int fd = cl_sys_open(fname, O_WRONLY, 0);
    if (fd < 0) {
        printk("open for write err '%d'.\n", fd);
        PANIC("bad dir fd.");
    }
    printk("%s: open dir fd '%d'\n", __func__, fd);

    int pos = cl_sys_lseek(fd, offset, SEEK_SET);
    CL_ASSERT(pos == offset, "seek error.");

    int err = cl_sys_write(fd, buf, len);
    if (err < 0) {
        printk("write err: %d\n", err);
        PANIC("write file err.");
    }

    if (cl_sys_close(fd)) {
        PANIC("close dir fd err.");
    }

    printk("\n============== file write ok! =============\n\n");
}

static void
test_file_truncate(const char *fname, long len)
{
    printk("\n============== file truncate ... =============\n\n");

    int err = cl_sys_truncate(fname, len);
    if (err < 0) {
        printk("truncate err: %d\n", err);
        PANIC("truncate file err.");
    }

    printk("\n============== file truncate ok! =============\n\n");
}

static void
test_file_common(const char *path, off_t offset)
{
    test_file_create(path);

    char wbuf[] = "1234";
    test_file_write(path, wbuf, sizeof(wbuf), offset);

    char rbuf[_BUF_LEN];
    int count = test_file_read(path, rbuf, sizeof(rbuf), offset);
    CL_ASSERT(count == sizeof(wbuf), "bad file size.");
    CL_ASSERT(memcmp(rbuf, wbuf, count) == 0, "bad file content.");

    test_stat(path);

    test_file_truncate(path, 0);

    test_file_remove(path);
}

static void test_simple(void)
{
    char fname[] = "/testf.txt";

    if (_exists(fname)) {
        panic("Success for '%s'!", fname);
    }

    int fd = cl_sys_open(fname, O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
    if (fd < 0) {
        PANIC("bad file fd.");
    }
    printk("create '%s' for write ok!\n", fname);
}

void test_ext4(void)
{
    test_simple();
#if 0
    for (int i = 0; i < 100; i++) {
        cl_resched(TASK_RUNNING);
    }
    {
        // Note: test dump_stack().
        int old_cpu, this_cpu;
        old_cpu = PANIC_CPU_INVALID;
        this_cpu = raw_smp_processor_id();

        /* atomic_try_cmpxchg updates old_cpu on failure */
        if (atomic_try_cmpxchg(&panic_cpu, &old_cpu, this_cpu)) {
            /* go ahead */
        } else if (old_cpu != this_cpu) {
            PANIC("INVALID panic cpu.");
        }
    }
#endif
    dump_stack();
    //PANIC("[Simple]: Reach here!");

    test_getdents64();

    test_file_common("/f1.txt", 0);
    test_file_common("/f1.txt", 512);

    test_dir_create("/dir1");

    test_file_common("/dir1/f1.txt", 0);

    test_stat("/dir1");

    test_dir_remove("/dir1");

#if 0
    /* Note: use 'sync_filesystem' to replace it. */
    printk("=========== %s: flush blkdev ...\n", __func__);
    int err = blkdev_issue_flush(root_inode->i_sb->s_bdev);
    printk("=========== %s: flush blkdev OK! err(%d)\n", __func__, err);
#endif
}
