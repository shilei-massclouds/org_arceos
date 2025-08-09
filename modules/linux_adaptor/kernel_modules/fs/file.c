#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/close_range.h>
#include <net/sock.h>
#include <linux/init_task.h>

#include "internal.h"
#include "../adaptor.h"

unsigned int sysctl_nr_open __read_mostly = 1024*1024;
unsigned int sysctl_nr_open_min = BITS_PER_LONG;

static unsigned int find_next_fd(struct fdtable *fdt, unsigned int start)
{
    unsigned int maxfd = fdt->max_fds; /* always multiple of BITS_PER_LONG */
    unsigned int maxbit = maxfd / BITS_PER_LONG;
    unsigned int bitbit = start / BITS_PER_LONG;

    bitbit = find_next_zero_bit(fdt->full_fds_bits, maxbit, bitbit) * BITS_PER_LONG;
    if (bitbit >= maxfd)
        return maxfd;
    if (bitbit > start)
        start = bitbit;
    return find_next_zero_bit(fdt->open_fds, maxfd, start);
}

/*
 * Expand files.
 * This function will expand the file structures, if the requested size exceeds
 * the current capacity and there is room for expansion.
 * Return <0 error code on error; 0 when nothing done; 1 when files were
 * expanded and execution may have blocked.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
static int expand_files(struct files_struct *files, unsigned int nr)
    __releases(files->file_lock)
    __acquires(files->file_lock)
{
    struct fdtable *fdt;
    int expanded = 0;

repeat:
    fdt = files_fdtable(files);

    /* Do we need to expand? */
    if (nr < fdt->max_fds)
        return expanded;

    /* Can we expand? */
    if (nr >= sysctl_nr_open)
        return -EMFILE;

    if (unlikely(files->resize_in_progress)) {
        spin_unlock(&files->file_lock);
        expanded = 1;
        wait_event(files->resize_wait, !files->resize_in_progress);
        spin_lock(&files->file_lock);
        goto repeat;
    }


    PANIC("");
}

static inline void __set_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
    __set_bit(fd, fdt->close_on_exec);
}

static inline void __clear_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
    if (test_bit(fd, fdt->close_on_exec))
        __clear_bit(fd, fdt->close_on_exec);
}

static inline void __set_open_fd(unsigned int fd, struct fdtable *fdt)
{
    __set_bit(fd, fdt->open_fds);
    fd /= BITS_PER_LONG;
    if (!~fdt->open_fds[fd])
        __set_bit(fd, fdt->full_fds_bits);
}

static inline void __clear_open_fd(unsigned int fd, struct fdtable *fdt)
{
    __clear_bit(fd, fdt->open_fds);
    __clear_bit(fd / BITS_PER_LONG, fdt->full_fds_bits);
}

/*
 * allocate a file descriptor, mark it busy.
 */
static int alloc_fd(unsigned start, unsigned end, unsigned flags)
{
    struct files_struct *files = current->files;
    unsigned int fd;
    int error;
    struct fdtable *fdt;

    spin_lock(&files->file_lock);
repeat:
    fdt = files_fdtable(files);
    fd = start;
    if (fd < files->next_fd)
        fd = files->next_fd;

    if (fd < fdt->max_fds)
        fd = find_next_fd(fdt, fd);

    /*
     * N.B. For clone tasks sharing a files structure, this test
     * will limit the total number of files that can be opened.
     */
    error = -EMFILE;
    if (fd >= end)
        goto out;

    error = expand_files(files, fd);
    if (error < 0)
        goto out;

    /*
     * If we needed to expand the fs array we
     * might have blocked - try again.
     */
    if (error)
        goto repeat;

    if (start <= files->next_fd)
        files->next_fd = fd + 1;

    __set_open_fd(fd, fdt);
    if (flags & O_CLOEXEC)
        __set_close_on_exec(fd, fdt);
    else
        __clear_close_on_exec(fd, fdt);
    error = fd;
#if 1
    /* Sanity check */
    if (rcu_access_pointer(fdt->fd[fd]) != NULL) {
        printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
        rcu_assign_pointer(fdt->fd[fd], NULL);
    }
#endif

out:
    spin_unlock(&files->file_lock);
    return error;
}

int __get_unused_fd_flags(unsigned flags, unsigned long nofile)
{
    return alloc_fd(0, nofile, flags);
}

int get_unused_fd_flags(unsigned flags)
{
    return __get_unused_fd_flags(flags, rlimit(RLIMIT_NOFILE));
}

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
    struct fdtable *fdt = files_fdtable(files);
    __clear_open_fd(fd, fdt);
    if (fd < files->next_fd)
        files->next_fd = fd;
}

void put_unused_fd(unsigned int fd)
{
    struct files_struct *files = current->files;
    spin_lock(&files->file_lock);
    __put_unused_fd(files, fd);
    spin_unlock(&files->file_lock);
}

/*
 * Install a file pointer in the fd array.
 *
 * The VFS is full of places where we drop the files lock between
 * setting the open_fds bitmap and installing the file in the file
 * array.  At any such point, we are vulnerable to a dup2() race
 * installing a file in the array before us.  We need to detect this and
 * fput() the struct file we are about to overwrite in this case.
 *
 * It should never happen - if we allow dup2() do it, _really_ bad things
 * will follow.
 *
 * This consumes the "file" refcount, so callers should treat it
 * as if they had called fput(file).
 */

void fd_install(unsigned int fd, struct file *file)
{
    struct files_struct *files = current->files;
    struct fdtable *fdt;

    if (WARN_ON_ONCE(unlikely(file->f_mode & FMODE_BACKING)))
        return;

    rcu_read_lock_sched();

    if (unlikely(files->resize_in_progress)) {
        rcu_read_unlock_sched();
        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        BUG_ON(fdt->fd[fd] != NULL);
        rcu_assign_pointer(fdt->fd[fd], file);
        spin_unlock(&files->file_lock);
        return;
    }
    /* coupled with smp_wmb() in expand_fdtable() */
    smp_rmb();
    fdt = rcu_dereference_sched(files->fdt);
    BUG_ON(fdt->fd[fd] != NULL);
    rcu_assign_pointer(fdt->fd[fd], file);
    rcu_read_unlock_sched();
}

struct files_struct init_files = {
    .count      = ATOMIC_INIT(1),
    .fdt        = &init_files.fdtab,
    .fdtab      = {
        .max_fds    = NR_OPEN_DEFAULT,
        .fd     = &init_files.fd_array[0],
        .close_on_exec  = init_files.close_on_exec_init,
        .open_fds   = init_files.open_fds_init,
        .full_fds_bits  = init_files.full_fds_bits_init,
    },
    .file_lock  = __SPIN_LOCK_UNLOCKED(init_files.file_lock),
    .resize_wait    = __WAIT_QUEUE_HEAD_INITIALIZER(init_files.resize_wait),
};
