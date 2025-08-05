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

static void test_basic(struct inode *root,
                       const char *fs_name,
                       const char *fname)
{
    /* Lookup inode of filesystem. */
    unsigned int lookup_flags = 0;
    struct dentry target;
    memset(&target, 0, sizeof(struct dentry));
    target.d_name.name = fname;
    target.d_name.len = strlen(target.d_name.name);
    target.d_name.hash = 0;

    root->i_op->lookup(root, &target, lookup_flags);

    struct inode *t_inode = target.d_inode;
    if (t_inode == NULL || t_inode->i_mapping == NULL) {
        PANIC("bad inode.");
    }
    printk("%s: target inode(%lx)\n", __func__, t_inode);

    printk("\n\n============== FS READ (first) =============\n\n");

    test_read(t_inode, fs_name);

    printk("\n\n============== FS WRITE (first) =============\n\n");

    test_write(t_inode, fs_name);

    printk("\n\n============== TEST FS OK! =============\n\n");
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

void test_ext4(struct dentry *root)
{
    struct inode *root_inode = prepare_inode(root);

    /*
     * Test read & write file.
     */
    test_basic(root_inode, "ext4", "ext4.txt");

    /*
     * Test dir iterate.
     */
    test_dir_iter(root_inode);
}
