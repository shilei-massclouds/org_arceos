#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/sched/xacct.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/splice.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include "internal.h"

#include <linux/uaccess.h>
#include <asm/unistd.h>

#include "../adaptor.h"

static inline bool unsigned_offsets(struct file *file)
{
    return file->f_op->fop_flags & FOP_UNSIGNED_OFFSET;
}

static int warn_unsupported(struct file *file, const char *op)
{
    pr_warn_ratelimited(
        "kernel %s not supported for file %pD4 (pid: %d comm: %.20s)\n",
        op, file, current->pid, current->comm);
    return -EINVAL;
}

static ssize_t new_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    struct kiocb kiocb;
    struct iov_iter iter;
    ssize_t ret;

    init_sync_kiocb(&kiocb, filp);
    kiocb.ki_pos = (ppos ? *ppos : 0);
    iov_iter_ubuf(&iter, ITER_DEST, buf, len);

    ret = filp->f_op->read_iter(&kiocb, &iter);
    BUG_ON(ret == -EIOCBQUEUED);
    if (ppos)
        *ppos = kiocb.ki_pos;
    printk("%s: ret(%d)\n", __func__, ret);
    return ret;
}

int rw_verify_area(int read_write, struct file *file, const loff_t *ppos, size_t count)
{
    int mask = read_write == READ ? MAY_READ : MAY_WRITE;
    int ret;

    if (unlikely((ssize_t) count < 0))
        return -EINVAL;

    if (ppos) {
        loff_t pos = *ppos;

        if (unlikely(pos < 0)) {
            if (!unsigned_offsets(file))
                return -EINVAL;
            if (count >= -pos) /* both values are in 0..LLONG_MAX */
                return -EOVERFLOW;
        } else if (unlikely((loff_t) (pos + count) < 0)) {
            if (!unsigned_offsets(file))
                return -EINVAL;
        }
    }

    return 0;
}

ssize_t kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
    ssize_t ret;

    ret = rw_verify_area(READ, file, pos, count);
    if (ret)
        return ret;
    return __kernel_read(file, buf, count, pos);
}

ssize_t __kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
    struct kvec iov = {
        .iov_base   = buf,
        .iov_len    = min_t(size_t, count, MAX_RW_COUNT),
    };
    struct kiocb kiocb;
    struct iov_iter iter;
    ssize_t ret;

    if (WARN_ON_ONCE(!(file->f_mode & FMODE_READ)))
        return -EINVAL;
    if (!(file->f_mode & FMODE_CAN_READ))
        return -EINVAL;
    /*
     * Also fail if ->read_iter and ->read are both wired up as that
     * implies very convoluted semantics.
     */
    if (unlikely(!file->f_op->read_iter || file->f_op->read))
        return warn_unsupported(file, "read");

    init_sync_kiocb(&kiocb, file);
    kiocb.ki_pos = pos ? *pos : 0;
    iov_iter_kvec(&iter, ITER_DEST, &iov, 1, iov.iov_len);
    ret = file->f_op->read_iter(&kiocb, &iter);
    if (ret > 0) {
        if (pos)
            *pos = kiocb.ki_pos;
        //fsnotify_access(file);
        add_rchar(current, ret);
    }
    inc_syscr(current);
    return ret;
}
