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

ssize_t kernel_write(struct file *file, const void *buf, size_t count,
                loff_t *pos)
{
    ssize_t ret;

    ret = rw_verify_area(WRITE, file, pos, count);
    if (ret)
        return ret;

    pr_err("%s: No impl for file_[start|end]_write.", __func__);
    //file_start_write(file);
    ret =  __kernel_write(file, buf, count, pos);
    //file_end_write(file);
    return ret;
}

/* caller is responsible for file_start_write/file_end_write */
ssize_t __kernel_write(struct file *file, const void *buf, size_t count, loff_t *pos)
{
    struct kvec iov = {
        .iov_base   = (void *)buf,
        .iov_len    = min_t(size_t, count, MAX_RW_COUNT),
    };
    struct iov_iter iter;
    iov_iter_kvec(&iter, ITER_SOURCE, &iov, 1, iov.iov_len);
    return __kernel_write_iter(file, &iter, pos);
}

/* caller is responsible for file_start_write/file_end_write */
ssize_t __kernel_write_iter(struct file *file, struct iov_iter *from, loff_t *pos)
{
    struct kiocb kiocb;
    ssize_t ret;

    printk("%s: step1 curr(%lx)\n", __func__, current);
    if (WARN_ON_ONCE(!(file->f_mode & FMODE_WRITE)))
        return -EBADF;
    if (!(file->f_mode & FMODE_CAN_WRITE))
        return -EINVAL;
    /*
     * Also fail if ->write_iter and ->write are both wired up as that
     * implies very convoluted semantics.
     */
    if (unlikely(!file->f_op->write_iter || file->f_op->write))
        return warn_unsupported(file, "write");

    init_sync_kiocb(&kiocb, file);
    kiocb.ki_pos = pos ? *pos : 0;
    ret = file->f_op->write_iter(&kiocb, from);
    if (ret > 0) {
        if (pos)
            *pos = kiocb.ki_pos;
        //fsnotify_modify(file);
        add_wchar(current, ret);
    }
    inc_syscw(current);
    printk("%s: stepN\n", __func__);
    return ret;
}

/*
 * Don't operate on ranges the page cache doesn't support, and don't exceed the
 * LFS limits.  If pos is under the limit it becomes a short access.  If it
 * exceeds the limit we return -EFBIG.
 */
int generic_write_check_limits(struct file *file, loff_t pos, loff_t *count)
{
    struct inode *inode = file->f_mapping->host;
    loff_t max_size = inode->i_sb->s_maxbytes;
    loff_t limit = rlimit(RLIMIT_FSIZE);

    if (limit != RLIM_INFINITY) {
        if (pos >= limit) {
            send_sig(SIGXFSZ, current, 0);
            return -EFBIG;
        }
        *count = min(*count, limit - pos);
    }

    if (!(file->f_flags & O_LARGEFILE))
        max_size = MAX_NON_LFS;

    if (unlikely(pos >= max_size))
        return -EFBIG;

    *count = min(*count, max_size - pos);

    return 0;
}

/* Like generic_write_checks(), but takes size of write instead of iter. */
int generic_write_checks_count(struct kiocb *iocb, loff_t *count)
{
    struct file *file = iocb->ki_filp;
    struct inode *inode = file->f_mapping->host;

    if (IS_SWAPFILE(inode))
        return -ETXTBSY;

    if (!*count)
        return 0;

    if (iocb->ki_flags & IOCB_APPEND)
        iocb->ki_pos = i_size_read(inode);

    if ((iocb->ki_flags & IOCB_NOWAIT) &&
        !((iocb->ki_flags & IOCB_DIRECT) ||
          (file->f_op->fop_flags & FOP_BUFFER_WASYNC)))
        return -EINVAL;

    return generic_write_check_limits(iocb->ki_filp, iocb->ki_pos, count);
}

/*
 * Performs necessary checks before doing a write
 *
 * Can adjust writing position or amount of bytes to write.
 * Returns appropriate error code that caller should return or
 * zero in case that write should be allowed.
 */
ssize_t generic_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
    loff_t count = iov_iter_count(from);
    int ret;

    ret = generic_write_checks_count(iocb, &count);
    if (ret)
        return ret;

    iov_iter_truncate(from, count);
    return iov_iter_count(from);
}
