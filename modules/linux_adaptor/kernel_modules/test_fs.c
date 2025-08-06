#include <linux/fs.h>
#include <linux/dirent.h>

#include "adaptor.h"

extern int verify_dirent_name(const char *name, int len);

struct getdents_callback64 {
    struct dir_context ctx;
    struct linux_dirent64 __user * current_dir;
    int prev_reclen;
    int count;
    int error;
};

static bool filldir64(struct dir_context *ctx, const char *name, int namlen,
                      loff_t offset, u64 ino, unsigned int d_type)
{
    struct linux_dirent64 __user *dirent, *prev;
    struct getdents_callback64 *buf =
        container_of(ctx, struct getdents_callback64, ctx);
    int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + namlen + 1,
        sizeof(u64));
    int prev_reclen;

    buf->error = verify_dirent_name(name, namlen);
    if (unlikely(buf->error))
        return false;
    buf->error = -EINVAL;   /* only used if we fail.. */
    if (reclen > buf->count)
        return false;
    prev_reclen = buf->prev_reclen;
    if (prev_reclen && signal_pending(current))
        return false;
    dirent = buf->current_dir;
    prev = (void __user *)dirent - prev_reclen;

    /* This might be 'dirent->d_off', but if so it will get overwritten */
    prev->d_off = offset;
    dirent->d_ino = ino;
    dirent->d_reclen = reclen;
    dirent->d_type = d_type;
    memcpy(dirent->d_name, name, namlen);

    buf->prev_reclen = reclen;
    buf->current_dir = (void __user *)dirent + reclen;
    buf->count -= reclen;

    return true;
}

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

static struct inode *
prepare_inode(struct dentry *root)
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

    return root_inode;
}

#if 0
static struct inode *
lookup_inode(struct inode *root, const char *fname)
{
    /* Lookup inode of filesystem. */
    unsigned int lookup_flags = 0;
    struct dentry *ret;
    struct dentry target;
    memset(&target, 0, sizeof(struct dentry));
    target.d_name.name = fname;
    target.d_name.len = strlen(target.d_name.name);
    target.d_name.hash = 0;

    ret = root->i_op->lookup(root, &target, lookup_flags);
    if (IS_ERR(ret)) {
        printk("%s: err(%d)\n", __func__, PTR_ERR(ret));
        PANIC("lookup error.");
    }
    return target.d_inode;
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

    printk("%s: step1\n", __func__);
    ret = parent_inode->i_op->lookup(parent_inode, target, lookup_flags);
    printk("%s: step2\n", __func__);
    if (IS_ERR(ret)) {
        printk("%s: err(%d)\n", __func__, PTR_ERR(ret));
        PANIC("lookup error.");
    }
    if (target->d_inode) {
        return target;
    }
    return NULL;
}

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

#define _DIR_BUF_LEN 512

static void test_dir_iter(struct inode *root)
{
    int ret;
    char dir_buf[_DIR_BUF_LEN] = {};
    char *pos = dir_buf;

    struct getdents_callback64 buf = {
        .ctx.actor = filldir64,
        .count = _DIR_BUF_LEN,
        .current_dir = (struct linux_dirent64 *) dir_buf
    };

    ret = _iterate_dir(root, &buf.ctx);
    if (ret >= 0)
        ret = buf.error;
    if (buf.prev_reclen) {
        struct linux_dirent64 *lastdirent;
        typeof(lastdirent->d_off) d_off = buf.ctx.pos;

        lastdirent = (void *) buf.current_dir - buf.prev_reclen;
        lastdirent->d_off = d_off;
        ret = _DIR_BUF_LEN - buf.count;
    }
    if (ret < 0) {
        PANIC("read dir error.");
    }

    printk("iterate dir ...\n");
    while (ret > 0) {
        struct linux_dirent64 *dirents = (struct linux_dirent64 *) pos;
        printk("name: %s, ino: %u, reclen: %u, ret: %u\n",
               dirents->d_name,
               dirents->d_ino,
               dirents->d_reclen,
               ret);

        ret -= dirents->d_reclen;
        pos += dirents->d_reclen;
    }

    printk("iterate dir Ok!\n");
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
        //delete_dir(root_dentry, dir);
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
    }

    printk("create file '%s' ..\n", fname);

    struct qstr qname = QSTR(fname);
    struct dentry *target = d_alloc(root_dentry, &qname);

    if (root->i_op->create(&nop_mnt_idmap, root, target, 0777|S_IFREG, false)) {
        PANIC("create dir error.");
    }

    printk("create file '%s' ok!\n", fname);

    find = lookup(root_dentry, fname);
    if (find == NULL) {
        PANIC("no file.");
    }
    struct inode *f = find->d_inode;
    printk("file i_mode(%x)\n", f->i_mode);
    test_write(f, "");

    printk("delete file '%s' ..\n", fname);

    if (root->i_op->unlink(root, find)) {
        PANIC("unlink dir error.");
    }

    find = lookup(root_dentry, fname);
    if (find) {
        PANIC("cannot delete file.");
    }

    printk("delete file '%s' ok!\n", fname);
}

void test_ext4(struct dentry *root)
{
    struct inode *root_inode = prepare_inode(root);

    /*
     * Test read & write file.
     */
    test_file_rw(root, "ext4", "ext4.txt");

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
}
