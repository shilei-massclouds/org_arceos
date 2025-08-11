#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/blkdev.h>
#include <linux/syscalls.h>

#include "adaptor.h"
#include "cl_syscalls.h"

unsigned long
cl_vfs_read(struct dentry *dentry, unsigned long offset, char *buf, size_t len)
{
    printk("%s: offset %lu, buflen %u\n", __func__, offset, len);
    if (dentry == NULL || dentry->d_inode == NULL) {
        PANIC("bad handle.");
    }
    struct inode *inode = dentry->d_inode;

    ssize_t ret;
    struct file file;
    memset(&file, 0, sizeof(struct file));
    file.f_inode = inode;
    file.f_mode |= FMODE_READ | FMODE_CAN_READ;
    file.f_mapping = inode->i_mapping;
    file.f_op = inode->i_fop;
    if (file.f_op == NULL) {
        PANIC("bad file_operations.");
    }

    loff_t _offset = offset;
    return kernel_read(&file, buf, len, &_offset);
}

#if 0
/* File level read. */
static void test_read(struct inode *inode, const char *fs_name)
{
    ssize_t ret;
    struct file file;
    memset(&file, 0, sizeof(struct file));
    file.f_inode = inode;
    file.f_mode |= FMODE_READ | FMODE_CAN_READ;
    file.f_mapping = inode->i_mapping;
    file.f_op = inode->i_fop;
    if (file.f_op == NULL) {
        PANIC("bad file_operations.");
    }

    loff_t pos = 0;
    char rbuf[256];
    memset(rbuf, 0, sizeof(rbuf));

    ret = kernel_read(&file, rbuf, sizeof(rbuf), &pos);
    printk("Read '%s': [%d]%s\n", fs_name, ret, rbuf);
}
#endif

unsigned long
cl_vfs_write(struct dentry *dentry, unsigned long offset, const char *buf, size_t len)
{
    printk("%s: offset %lu, buf %x,%x, len %u\n", __func__, offset, buf[0], buf[1], len);
    if (dentry == NULL || dentry->d_inode == NULL) {
        PANIC("bad handle.");
    }
    struct inode *inode = dentry->d_inode;

    ssize_t ret;
    struct file file;
    memset(&file, 0, sizeof(struct file));
    file.f_inode = inode;
    file.f_mode |= FMODE_WRITE | FMODE_CAN_WRITE;
    file.f_mapping = inode->i_mapping;
    file.f_op = inode->i_fop;
    if (file.f_op == NULL) {
        PANIC("bad file_operations.");
    }

    // Note: set IOCB_DSYNC for sync.
    file.f_iocb_flags |= IOCB_DSYNC;

    loff_t _offset = offset;
    return kernel_write(&file, buf, len, &_offset);
}

#if 0
/* File level write. */
static void test_write(struct inode *inode, const char *fs_name)
{
    ssize_t ret;
    struct file file;
    memset(&file, 0, sizeof(struct file));
    file.f_inode = inode;
    file.f_mode |= FMODE_WRITE | FMODE_CAN_WRITE;
    file.f_mapping = inode->i_mapping;
    file.f_op = inode->i_fop;
    if (file.f_op == NULL) {
        PANIC("bad file_operations.");
    }

    // Note: set IOCB_DSYNC for sync.
    file.f_iocb_flags |= IOCB_DSYNC;

    loff_t pos = 0;
    char wbuf[] = "bcde";

    ret = kernel_write(&file, wbuf, sizeof(wbuf), &pos);
    printk("Write '%s' to '%s': ret [%d]\n", wbuf, fs_name, ret);
    if (ret <= 0) {
        PANIC("write error!");
    }
}

#endif

static struct dentry *
lookup(struct dentry *parent, const char *name)
{
    /* Lookup inode by name in parent dir. */
    struct dentry *ret;
    struct inode *parent_inode = parent->d_inode;
    unsigned int lookup_flags = 0;
    struct qstr qname = QSTR(name);
    struct dentry *target = d_alloc(parent, &qname);

    printk("------> %s: step1 parent(%lx) name(%s)\n",
           __func__, parent, name);
    ret = parent_inode->i_op->lookup(parent_inode, target, lookup_flags);
    if (IS_ERR(ret)) {
        printk("%s: err(%d)\n", __func__, PTR_ERR(ret));
        PANIC("lookup error.");
    }
    printk("%s: step2 inode(%lx)\n", __func__, target->d_inode);
    if (target->d_inode) {
        return target;
    }
    dput(target);
    return NULL;
}

/**
 * cl_vfs_file_size - get size of file
 * @dentry: file dentry pointer
 *
 * Return: size of the file
 */
unsigned long
cl_vfs_file_size(struct dentry *dentry)
{
    if (dentry == NULL || dentry->d_inode == NULL) {
        PANIC("bad dentry without inode.");
    }
    return (unsigned long) dentry->d_inode->i_size;
}

/**
 * cl_vfs_exists - check whether a file or dir exists
 * @parent: parent dir of the file or dir
 * @name: name of this file or dir
 *
 * Return: 1 on existence, 0 on none-existence.
 */
unsigned long
cl_vfs_exists(struct dentry *parent, const char *name)
{
    printk("%s: name '%s' len %d\n", __func__, name, strlen(name));
    struct dentry *target = lookup(parent, name);
    if (target) {
        dput(target);
        return 1;
    }
    return 0;
}

/**
 * cl_vfs_lookup - lookup a file or dir at parent dir
 * @parent: parent dir
 * @name: name of target file or dir
 * @ret_type: pointer to the node's type
 *
 * Return: target entry ptr on success, NULL(0) on failure.
 */
unsigned long
cl_vfs_lookup(struct dentry *parent, const char *name, unsigned char *ret_type)
{
    struct dentry *dentry = lookup(parent, name);
    if (dentry == NULL) {
        return 0;
    }

    if (dentry->d_inode == NULL) {
        PANIC("bad dentry without inode.");
    }

    unsigned char d_type = 0;
    struct inode *inode = dentry->d_inode;
    if (S_ISREG(inode->i_mode)) {
        d_type = DT_REG;
    } else if (S_ISDIR(inode->i_mode)) {
        d_type = DT_DIR;
    } else {
        PANIC("bad type.");
    }
    *ret_type = d_type;

    printk("%s: name '%s' len %d type %u\n", __func__, name, strlen(name), d_type);
    return (unsigned long) dentry;
}

/**
 * cl_vfs_parent - lookup parent of the file or dir
 * @curr: curr file or dir
 *
 * Return: parent entry ptr
 */
unsigned long
cl_vfs_parent(struct dentry *curr)
{
    return (unsigned long) curr->d_parent;
}

#if 0
static void test_file_rw(struct dentry *root,
                         const char *fs_name,
                         const char *fname)
{
    printk("\n\n============== LOOKUP FILE =============\n\n");

    struct dentry *target;
    target = lookup(root, fname);
    if (target == NULL || target->d_inode == NULL) {
        PANIC("bad dentry.");
    }

    printk("\n\n============== FILE READ (first) =============\n\n");

    test_read(target->d_inode, fs_name);

    printk("\n\n============== FILE WRITE (first) =============\n\n");

    test_write(target->d_inode, fs_name);

    printk("\n\n============== FILE RW OK! =============\n\n");
}

static int _iterate_dir(struct inode *inode, struct dir_context *ctx)
{
    int res = -ENOTDIR;

    if (!inode->i_fop->iterate_shared)
        goto out;

    res = down_read_killable(&inode->i_rwsem);
    if (res)
        goto out;

    res = -ENOENT;
    if (!IS_DEADDIR(inode)) {
        struct file file;
        memset(&file, 0, sizeof(struct file));
        file.f_inode = inode;

        res = inode->i_fop->open(inode, &file);
        if (res != 0) {
            PANIC("open dir error.");
        }

        res = inode->i_fop->iterate_shared(&file, ctx);
    }
    inode_unlock_shared(inode);
out:
    return res;
}
#endif

unsigned long
cl_vfs_read_dir(struct dentry *dentry, char *ptr, size_t len)
{
#if 0
    int ret;
    struct getdents_callback64 buf = {
        .ctx.actor = filldir64,
        .count = len,
        .current_dir = (struct linux_dirent64 *) ptr
    };

    ret = _iterate_dir(dentry->d_inode, &buf.ctx);
    if (ret >= 0)
        ret = buf.error;
    if (buf.prev_reclen) {
        struct linux_dirent64 *lastdirent;
        typeof(lastdirent->d_off) d_off = buf.ctx.pos;

        lastdirent = (void *) buf.current_dir - buf.prev_reclen;
        lastdirent->d_off = d_off;
        ret = len - buf.count;
    }
    return (unsigned long) ret;
#endif
    PANIC("");
}

static struct dentry *
create_dir(struct dentry *parent, const char *dname)
{
    struct inode *parent_inode = parent->d_inode;
    struct qstr qname = QSTR(dname);
    struct dentry *target = d_alloc(parent, &qname);

    if (parent_inode->i_op->mkdir(&nop_mnt_idmap, parent_inode, target, 0777)) {
        PANIC("create dir error.");
    }
    if (target->d_inode == NULL) {
        PANIC("bad dentry for no inode.");
    }

    return target;
}

unsigned long
cl_vfs_create_dir(struct dentry *parent, const char *dname)
{
    struct dentry *ret = create_dir(parent, dname);
    if (IS_ERR(ret)) {
        return PTR_ERR(ret);
    }
    dput(ret);
    return 0;
}

static struct dentry *
create_file(struct dentry *parent, const char *fname)
{
    struct inode *parent_inode = parent->d_inode;
    struct qstr qname = QSTR(fname);
    struct dentry *target = d_alloc(parent, &qname);

    if (parent_inode->i_op->create(&nop_mnt_idmap, parent_inode, target, 0777|S_IFREG, false)) {
        PANIC("create file error.");
    }
    if (target->d_inode == NULL) {
        PANIC("bad dentry for no inode.");
    }

    printk("%s: create '%s' ok!\n", __func__, fname);
    return target;
}

unsigned long
cl_vfs_create_file(struct dentry *parent, const char *fname)
{
    struct dentry *ret = create_file(parent, fname);
    if (IS_ERR(ret)) {
        return PTR_ERR(ret);
    }
    dput(ret);
    return 0;
}

unsigned long
cl_vfs_remove(struct dentry *parent, const char *name)
{
    struct inode *parent_inode = parent->d_inode;
    if (parent_inode == NULL) {
        PANIC("No parent inode.");
    }

    printk("%s: remove '%s' ...\n", __func__, name);
    struct dentry *target = lookup(parent, name);
    if (target == NULL) {
        PANIC("No target dentry.");
    }
    struct inode *inode = target->d_inode;
    if (S_ISREG(inode->i_mode)) {
        if (parent_inode->i_op->unlink(parent_inode, target)) {
            PANIC("unlink dir error.");
        }
        printk("%s: remove file '%s' ok!\n", __func__, name);
    } else if (S_ISDIR(inode->i_mode)) {
        if (parent_inode->i_op->rmdir(parent_inode, target)) {
            PANIC("delete dir error.");
        }
        printk("%s: remove dir '%s' ok!\n", __func__, name);
    } else {
        PANIC("bad type.");
    }
    dput(target);
    return 0;
}

#if 0
static int
delete_dir(struct dentry *parent, struct dentry *target)
{
    struct inode *parent_inode = parent->d_inode;
#if 0
    struct dentry *target = lookup(parent, dname);
    if (target == NULL) {
        printk("No target dentry '%s'.", dname);
        PANIC("No target dentry.");
    }
    struct qstr qname = QSTR(dname);
    struct dentry *target = d_alloc(parent, &qname);
    target->d_inode = inode;
#endif

    if (parent_inode->i_op->rmdir(parent_inode, target)) {
        PANIC("delete dir error.");
    }

    return 0;
}

static void test_dir_ops(struct dentry *root_dentry, const char *dirname)
{
    printk("\n\n============== DIR CREATE && DELETE =============\n\n");
    printk("check dir '%s' ..\n", dirname);

    struct inode *root = root_dentry->d_inode;
    struct dentry *dir = lookup(root_dentry, dirname);
    if (dir) {
        printk("dir '%s' already exists.\n", dirname);
        PANIC("dir already exists.");
    }

    printk("create dir '%s' ..\n", dirname);

    dir = create_dir(root_dentry, dirname);

    printk("create dir '%s' ok!\n", dirname);

    printk("delete dir '%s' ..\n", dirname);

    delete_dir(root_dentry, dir);

    printk("delete dir '%s' ok!\n", dirname);
}

static void test_file_ops(struct dentry *root_dentry, const char *fname)
{
    printk("\n\n============== FILE CREATE && DELETE =============\n\n");

    struct inode *root = root_dentry->d_inode;
    struct dentry *find = lookup(root_dentry, fname);
    if (find) {
        printk("file '%s' already exists.\n", fname);
        if (root->i_op->unlink(root, find)) {
            PANIC("unlink dir error.");
        }
        find = lookup(root_dentry, fname);
        if (find) {
            PANIC("cannot delete file.");
        }
        //PANIC("file already exists.");
    }

    printk("create file '%s' ..\n", fname);

    struct qstr qname = QSTR(fname);
    struct dentry *target = d_alloc(root_dentry, &qname);

    if (root->i_op->create(&nop_mnt_idmap, root, target, 0777|S_IFREG, false)) {
        PANIC("create dir error.");
    }
    dput(target);

    printk("create file '%s' ok!\n", fname);

    find = lookup(root_dentry, fname);
    if (find == NULL) {
        PANIC("no file.");
    }
    struct inode *f = find->d_inode;
    printk("file i_mode(%x)\n", f->i_mode);
    test_write(f, "");

    printk("write file '%s' count(%d) ok!\n", fname, f->i_count);

    printk("delete file '%s' ..\n", fname);

    if (root->i_op->unlink(root, find)) {
        PANIC("unlink dir error.");
    }
    dput(find);

    find = lookup(root_dentry, fname);
    if (find) {
        PANIC("cannot delete file.");
    }

    printk("delete file '%s' ok!\n", fname);
}
#endif

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
    printk("\n============== getdents64 ... =============\n");

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
    printk("\n============== file create ... =============\n");

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
    printk("\n============== dir create ... =============\n");

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
test_file_remove(const char *fname)
{
    printk("\n============== file remove ... =============\n");

    int err = cl_sys_unlink(fname);
    if (err < 0) {
        PANIC("remove file err.");
    }

    CL_ASSERT(!_exists(fname), "Found file after removing it.");

    printk("\n============== file remove ok! =============\n\n");
}

static void
test_file_stat(const char *fname)
{
    printk("\n============== file stat ... =============\n");

    struct stat buf;
    int err = cl_sys_newstat(fname, &buf);
    if (err < 0) {
        if (err == -ENOENT) {
            PANIC("No such file.\n");
        } else {
            printk("stat err: %d\n", err);
            PANIC("get file stat err.");
        }
    } else {
        printk("[%s] ino: %lu, mode: %u, size: %ld\n",
               fname, buf.st_ino, buf.st_mode, buf.st_size);
        if (S_ISREG(buf.st_mode)) {
            printk("It is a FILE.\n");
        } else if (S_ISDIR(buf.st_mode)) {
            printk("It is a DIR.\n");
        } else {
            printk("It is other types.\n");
        }
    }

    printk("\n============== file stat ok! =============\n\n");
}

static int
test_file_read(const char *fname, char *buf, size_t len)
{
    printk("\n============== file read ... =============\n");

    int fd = cl_sys_open(fname, O_RDONLY, 0);
    if (fd < 0) {
        printk("open for read err '%d'.\n", fd);
        PANIC("bad dir fd.");
    }
    printk("%s: open dir fd '%d'\n", __func__, fd);

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
test_file_write(const char *fname, const char *buf, size_t len)
{
    printk("\n============== file write ... =============\n");

    int fd = cl_sys_open(fname, O_WRONLY, 0);
    if (fd < 0) {
        printk("open for write err '%d'.\n", fd);
        PANIC("bad dir fd.");
    }
    printk("%s: open dir fd '%d'\n", __func__, fd);

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
test_file_common(const char *path)
{
    test_file_create(path);

    char wbuf[] = "1234";
    test_file_write(path, wbuf, sizeof(wbuf));

    char rbuf[_BUF_LEN];
    int count = test_file_read(path, rbuf, sizeof(rbuf));
    CL_ASSERT(count == sizeof(wbuf), "bad file size.");
    CL_ASSERT(memcmp(rbuf, wbuf, count) == 0, "bad file content.");

    test_file_stat(path);

    test_file_remove(path);
}

void test_ext4(void)
{
    test_getdents64();

    test_file_common("/f1.txt");

    test_dir_create("/dir1");

    PANIC("Reach here!");

#if 0
    /*
     * Test dir iterate.
     */
    test_dir_iter(root_inode);

    /*
     * Test create/delete dir.
     */
    test_dir_ops(root, "new_dir");

    /*
     * Test create/delete dir.
     */
    test_file_ops(root, "new_file");

    /*
     * Test dir iterate (again).
     */
    test_dir_iter(root_inode);

    /* Note: use 'sync_filesystem' to replace it. */
    printk("=========== %s: flush blkdev ...\n", __func__);
    int err = blkdev_issue_flush(root_inode->i_sb->s_bdev);
    printk("=========== %s: flush blkdev OK! err(%d)\n", __func__, err);
#endif
}
