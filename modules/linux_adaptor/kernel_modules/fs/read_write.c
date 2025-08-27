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

static ssize_t new_sync_read(struct file *filp, char *buf, size_t len, loff_t *ppos)
{
    struct kvec iov = {
        .iov_base   = buf,
        .iov_len    = min_t(size_t, len, MAX_RW_COUNT),
    };
    struct kiocb kiocb;
    struct iov_iter iter;
    ssize_t ret;

    init_sync_kiocb(&kiocb, filp);
    kiocb.ki_pos = (ppos ? *ppos : 0);
    iov_iter_kvec(&iter, ITER_DEST, &iov, 1, iov.iov_len);

    ret = filp->f_op->read_iter(&kiocb, &iter);
    BUG_ON(ret == -EIOCBQUEUED);
    if (ppos)
        *ppos = kiocb.ki_pos;
    return ret;
}

static ssize_t new_sync_write(struct file *filp, const char *buf, size_t len, loff_t *ppos)
{
    struct kvec iov = {
        .iov_base   = (void *)buf,
        .iov_len    = min_t(size_t, len, MAX_RW_COUNT),
    };
    struct kiocb kiocb;
    struct iov_iter iter;
    ssize_t ret;

    init_sync_kiocb(&kiocb, filp);
    kiocb.ki_pos = (ppos ? *ppos : 0);
    iov_iter_kvec(&iter, ITER_SOURCE, &iov, 1, iov.iov_len);

    ret = filp->f_op->write_iter(&kiocb, &iter);
    BUG_ON(ret == -EIOCBQUEUED);
    if (ret > 0 && ppos)
        *ppos = kiocb.ki_pos;
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

int cl_sys_read(unsigned int fd, char *buf, size_t count)
{
    return ksys_read(fd, buf, count);
}

/* file_ppos returns &file->f_pos or NULL if file is stream */
static inline loff_t *file_ppos(struct file *file)
{
    return file->f_mode & FMODE_STREAM ? NULL : &file->f_pos;
}

ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
    struct fd f = fdget_pos(fd);
    ssize_t ret = -EBADF;

    if (fd_file(f)) {
        loff_t pos, *ppos = file_ppos(fd_file(f));
        if (ppos) {
            pos = *ppos;
            ppos = &pos;
        }
        ret = vfs_read(fd_file(f), buf, count, ppos);
        if (ret >= 0 && ppos)
            fd_file(f)->f_pos = pos;
        fdput_pos(f);
    }
    return ret;
}

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    ssize_t ret;

    if (!(file->f_mode & FMODE_READ))
        return -EBADF;
    if (!(file->f_mode & FMODE_CAN_READ))
        return -EINVAL;

    ret = rw_verify_area(READ, file, pos, count);
    if (ret)
        return ret;
    if (count > MAX_RW_COUNT)
        count =  MAX_RW_COUNT;

    if (file->f_op->read)
        ret = file->f_op->read(file, buf, count, pos);
    else if (file->f_op->read_iter)
        ret = new_sync_read(file, buf, count, pos);
    else
        ret = -EINVAL;
    if (ret > 0) {
        fsnotify_access(file);
        add_rchar(current, ret);
    }
    inc_syscr(current);
    return ret;
}

ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
    struct fd f = fdget_pos(fd);
    ssize_t ret = -EBADF;

    if (fd_file(f)) {
        loff_t pos, *ppos = file_ppos(fd_file(f));
        if (ppos) {
            pos = *ppos;
            ppos = &pos;
        }
        ret = vfs_write(fd_file(f), buf, count, ppos);
        if (ret >= 0 && ppos)
            fd_file(f)->f_pos = pos;
        fdput_pos(f);
    }

    return ret;
}

int cl_sys_write(unsigned int fd, const char *buf, size_t count)
{
    return ksys_write(fd, buf, count);
}

ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    ssize_t ret;

    if (!(file->f_mode & FMODE_WRITE))
        return -EBADF;
    if (!(file->f_mode & FMODE_CAN_WRITE))
        return -EINVAL;

    ret = rw_verify_area(WRITE, file, pos, count);
    if (ret)
        return ret;
    if (count > MAX_RW_COUNT)
        count =  MAX_RW_COUNT;
    file_start_write(file);
    if (file->f_op->write)
        ret = file->f_op->write(file, buf, count, pos);
    else if (file->f_op->write_iter)
        ret = new_sync_write(file, buf, count, pos);
    else
        ret = -EINVAL;
    if (ret > 0) {
        fsnotify_modify(file);
        add_wchar(current, ret);
    }
    inc_syscw(current);
    file_end_write(file);
    return ret;
}

static off_t ksys_lseek(unsigned int fd, off_t offset, unsigned int whence)
{
    off_t retval;
    struct fd f = fdget_pos(fd);
    if (!fd_file(f))
        return -EBADF;

    retval = -EINVAL;
    if (whence <= SEEK_MAX) {
        loff_t res = vfs_llseek(fd_file(f), offset, whence);
        retval = res;
        if (res != (loff_t)retval)
            retval = -EOVERFLOW;    /* LFS: should only happen on 32 bit platforms */
    }
    fdput_pos(f);
    return retval;
}

int cl_sys_lseek(unsigned int fd, off_t offset, unsigned int whence)
{
    return ksys_lseek(fd, offset, whence);
}

loff_t vfs_llseek(struct file *file, loff_t offset, int whence)
{
    if (!(file->f_mode & FMODE_LSEEK))
        return -ESPIPE;
    return file->f_op->llseek(file, offset, whence);
}

/**
 * must_set_pos - check whether f_pos has to be updated
 * @file: file to seek on
 * @offset: offset to use
 * @whence: type of seek operation
 * @eof: end of file
 *
 * Check whether f_pos needs to be updated and update @offset according
 * to @whence.
 *
 * Return: 0 if f_pos doesn't need to be updated, 1 if f_pos has to be
 * updated, and negative error code on failure.
 */
static int must_set_pos(struct file *file, loff_t *offset, int whence, loff_t eof)
{
    switch (whence) {
    case SEEK_END:
        *offset += eof;
        break;
    case SEEK_CUR:
        /*
         * Here we special-case the lseek(fd, 0, SEEK_CUR)
         * position-querying operation.  Avoid rewriting the "same"
         * f_pos value back to the file because a concurrent read(),
         * write() or lseek() might have altered it
         */
        if (*offset == 0) {
            *offset = file->f_pos;
            return 0;
        }
        break;
    case SEEK_DATA:
        /*
         * In the generic case the entire file is data, so as long as
         * offset isn't at the end of the file then the offset is data.
         */
        if ((unsigned long long)*offset >= eof)
            return -ENXIO;
        break;
    case SEEK_HOLE:
        /*
         * There is a virtual hole at the end of the file, so as long as
         * offset isn't i_size or larger, return i_size.
         */
        if ((unsigned long long)*offset >= eof)
            return -ENXIO;
        *offset = eof;
        break;
    }

    return 1;
}

/**
 * generic_file_llseek_size - generic llseek implementation for regular files
 * @file:   file structure to seek on
 * @offset: file offset to seek to
 * @whence: type of seek
 * @maxsize:    max size of this file in file system
 * @eof:    offset used for SEEK_END position
 *
 * This is a variant of generic_file_llseek that allows passing in a custom
 * maximum file size and a custom EOF position, for e.g. hashed directories
 *
 * Synchronization:
 * SEEK_SET and SEEK_END are unsynchronized (but atomic on 64bit platforms)
 * SEEK_CUR is synchronized against other SEEK_CURs, but not read/writes.
 * read/writes behave like SEEK_SET against seeks.
 */
loff_t
generic_file_llseek_size(struct file *file, loff_t offset, int whence,
        loff_t maxsize, loff_t eof)
{
    int ret;

    ret = must_set_pos(file, &offset, whence, eof);
    if (ret < 0)
        return ret;
    if (ret == 0)
        return offset;

    if (whence == SEEK_CUR) {
        /*
         * f_lock protects against read/modify/write race with
         * other SEEK_CURs. Note that parallel writes and reads
         * behave like SEEK_SET.
         */
        guard(spinlock)(&file->f_lock);
        return vfs_setpos(file, file->f_pos + offset, maxsize);
    }

    return vfs_setpos(file, offset, maxsize);
}

/**
 * vfs_setpos_cookie - update the file offset for lseek and reset cookie
 * @file:   file structure in question
 * @offset: file offset to seek to
 * @maxsize:    maximum file size
 * @cookie: cookie to reset
 *
 * Update the file offset to the value specified by @offset if the given
 * offset is valid and it is not equal to the current file offset and
 * reset the specified cookie to indicate that a seek happened.
 *
 * Return the specified offset on success and -EINVAL on invalid offset.
 */
static loff_t vfs_setpos_cookie(struct file *file, loff_t offset,
                loff_t maxsize, u64 *cookie)
{
    if (offset < 0 && !unsigned_offsets(file))
        return -EINVAL;
    if (offset > maxsize)
        return -EINVAL;

    if (offset != file->f_pos) {
        file->f_pos = offset;
        if (cookie)
            *cookie = 0;
    }
    return offset;
}

/**
 * vfs_setpos - update the file offset for lseek
 * @file:   file structure in question
 * @offset: file offset to seek to
 * @maxsize:    maximum file size
 *
 * This is a low-level filesystem helper for updating the file offset to
 * the value specified by @offset if the given offset is valid and it is
 * not equal to the current file offset.
 *
 * Return the specified offset on success and -EINVAL on invalid offset.
 */
loff_t vfs_setpos(struct file *file, loff_t offset, loff_t maxsize)
{
    return vfs_setpos_cookie(file, offset, maxsize, NULL);
}
