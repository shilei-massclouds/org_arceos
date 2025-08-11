#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#include <linux/audit.h>
#include <linux/falloc.h>
#include <linux/fs_struct.h>
#include <linux/dnotify.h>
#include <linux/compat.h>
#include <linux/mnt_idmapping.h>
#include <linux/filelock.h>

#include "internal.h"
#include "../adaptor.h"

#define WILL_CREATE(flags)  (flags & (O_CREAT | __O_TMPFILE))
#define O_PATH_FLAGS        (O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC)

inline struct open_how build_open_how(int flags, umode_t mode)
{
    struct open_how how = {
        .flags = flags & VALID_OPEN_FLAGS,
        .mode = mode & S_IALLUGO,
    };

    /* O_PATH beats everything else. */
    if (how.flags & O_PATH)
        how.flags &= O_PATH_FLAGS;
    /* Modes should only be set for create-like flags. */
    if (!WILL_CREATE(how.flags))
        how.mode = 0;
    return how;
}

int cl_sys_open(const char *filename, int flags, umode_t mode)
{
    if (force_o_largefile())
        flags |= O_LARGEFILE;
    return do_sys_open(AT_FDCWD, filename, flags, mode);
}

inline int build_open_flags(const struct open_how *how, struct open_flags *op)
{
	u64 flags = how->flags;
	u64 strip = __FMODE_NONOTIFY | O_CLOEXEC;
	int lookup_flags = 0;
	int acc_mode = ACC_MODE(flags);

	BUILD_BUG_ON_MSG(upper_32_bits(VALID_OPEN_FLAGS),
			 "struct open_flags doesn't yet handle flags > 32 bits");

	/*
	 * Strip flags that either shouldn't be set by userspace like
	 * FMODE_NONOTIFY or that aren't relevant in determining struct
	 * open_flags like O_CLOEXEC.
	 */
	flags &= ~strip;

	/*
	 * Older syscalls implicitly clear all of the invalid flags or argument
	 * values before calling build_open_flags(), but openat2(2) checks all
	 * of its arguments.
	 */
	if (flags & ~VALID_OPEN_FLAGS)
		return -EINVAL;
	if (how->resolve & ~VALID_RESOLVE_FLAGS)
		return -EINVAL;

	/* Scoping flags are mutually exclusive. */
	if ((how->resolve & RESOLVE_BENEATH) && (how->resolve & RESOLVE_IN_ROOT))
		return -EINVAL;

	/* Deal with the mode. */
	if (WILL_CREATE(flags)) {
		if (how->mode & ~S_IALLUGO)
			return -EINVAL;
		op->mode = how->mode | S_IFREG;
	} else {
		if (how->mode != 0)
			return -EINVAL;
		op->mode = 0;
	}

	/*
	 * Block bugs where O_DIRECTORY | O_CREAT created regular files.
	 * Note, that blocking O_DIRECTORY | O_CREAT here also protects
	 * O_TMPFILE below which requires O_DIRECTORY being raised.
	 */
	if ((flags & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT))
		return -EINVAL;

	/* Now handle the creative implementation of O_TMPFILE. */
	if (flags & __O_TMPFILE) {
		/*
		 * In order to ensure programs get explicit errors when trying
		 * to use O_TMPFILE on old kernels we enforce that O_DIRECTORY
		 * is raised alongside __O_TMPFILE.
		 */
		if (!(flags & O_DIRECTORY))
			return -EINVAL;
		if (!(acc_mode & MAY_WRITE))
			return -EINVAL;
	}
	if (flags & O_PATH) {
		/* O_PATH only permits certain other flags to be set. */
		if (flags & ~O_PATH_FLAGS)
			return -EINVAL;
		acc_mode = 0;
	}

	/*
	 * O_SYNC is implemented as __O_SYNC|O_DSYNC.  As many places only
	 * check for O_DSYNC if the need any syncing at all we enforce it's
	 * always set instead of having to deal with possibly weird behaviour
	 * for malicious applications setting only __O_SYNC.
	 */
	if (flags & __O_SYNC)
		flags |= O_DSYNC;

	op->open_flag = flags;

	/* O_TRUNC implies we need access checks for write permissions */
	if (flags & O_TRUNC)
		acc_mode |= MAY_WRITE;

	/* Allow the LSM permission hook to distinguish append
	   access from general write access. */
	if (flags & O_APPEND)
		acc_mode |= MAY_APPEND;

	op->acc_mode = acc_mode;

	op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

	if (flags & O_CREAT) {
		op->intent |= LOOKUP_CREATE;
		if (flags & O_EXCL) {
			op->intent |= LOOKUP_EXCL;
			flags |= O_NOFOLLOW;
		}
	}

	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;

	if (how->resolve & RESOLVE_NO_XDEV)
		lookup_flags |= LOOKUP_NO_XDEV;
	if (how->resolve & RESOLVE_NO_MAGICLINKS)
		lookup_flags |= LOOKUP_NO_MAGICLINKS;
	if (how->resolve & RESOLVE_NO_SYMLINKS)
		lookup_flags |= LOOKUP_NO_SYMLINKS;
	if (how->resolve & RESOLVE_BENEATH)
		lookup_flags |= LOOKUP_BENEATH;
	if (how->resolve & RESOLVE_IN_ROOT)
		lookup_flags |= LOOKUP_IN_ROOT;
	if (how->resolve & RESOLVE_CACHED) {
		/* Don't bother even trying for create/truncate/tmpfile open */
		if (flags & (O_TRUNC | O_CREAT | __O_TMPFILE))
			return -EAGAIN;
		lookup_flags |= LOOKUP_CACHED;
	}

	op->lookup_flags = lookup_flags;
	return 0;
}

static long do_sys_openat2(int dfd, const char __user *filename,
               struct open_how *how)
{
    struct open_flags op;
    int fd = build_open_flags(how, &op);
    struct filename *tmp;

    if (fd)
        return fd;

    tmp = getname(filename);
    if (IS_ERR(tmp))
        return PTR_ERR(tmp);

    fd = get_unused_fd_flags(how->flags);
    if (fd >= 0) {
        struct file *f = do_filp_open(dfd, tmp, &op);
        if (IS_ERR(f)) {
            put_unused_fd(fd);
            fd = PTR_ERR(f);
        } else {
            fd_install(fd, f);
        }
    }
    putname(tmp);
    return fd;
}

long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct open_how how = build_open_how(flags, mode);
    return do_sys_openat2(dfd, filename, &how);
}

static inline int file_get_write_access(struct file *f)
{
    int error;

    error = get_write_access(f->f_inode);
    if (unlikely(error))
        return error;
    error = mnt_get_write_access(f->f_path.mnt);
    if (unlikely(error))
        goto cleanup_inode;
    if (unlikely(f->f_mode & FMODE_BACKING)) {
        error = mnt_get_write_access(backing_file_user_path(f)->mnt);
        if (unlikely(error))
            goto cleanup_mnt;
    }
    return 0;

cleanup_mnt:
    mnt_put_write_access(f->f_path.mnt);
cleanup_inode:
    put_write_access(f->f_inode);
    return error;

}

static int do_dentry_open(struct file *f,
              int (*open)(struct inode *, struct file *))
{
    static const struct file_operations empty_fops = {};
    struct inode *inode = f->f_path.dentry->d_inode;
    int error;

    path_get(&f->f_path);
    f->f_inode = inode;
    f->f_mapping = inode->i_mapping;
    f->f_wb_err = filemap_sample_wb_err(f->f_mapping);
    f->f_sb_err = file_sample_sb_err(f);

    if (unlikely(f->f_flags & O_PATH)) {
        f->f_mode = FMODE_PATH | FMODE_OPENED;
        f->f_op = &empty_fops;
        return 0;
    }

    if ((f->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ) {
        i_readcount_inc(inode);
    } else if (f->f_mode & FMODE_WRITE && !special_file(inode->i_mode)) {
        error = file_get_write_access(f);
        if (unlikely(error))
            goto cleanup_file;
        f->f_mode |= FMODE_WRITER;
    }

    /* POSIX.1-2008/SUSv4 Section XSI 2.9.7 */
    if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))
        f->f_mode |= FMODE_ATOMIC_POS;

    f->f_op = fops_get(inode->i_fop);
    if (WARN_ON(!f->f_op)) {
        error = -ENODEV;
        goto cleanup_all;
    }

    error = security_file_open(f);
    if (error)
        goto cleanup_all;

    error = break_lease(file_inode(f), f->f_flags);
    if (error)
        goto cleanup_all;

    /* normally all 3 are set; ->open() can clear them if needed */
    f->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
    if (!open)
        open = f->f_op->open;
    if (open) {
        error = open(inode, f);
        if (error)
            goto cleanup_all;
    }
    f->f_mode |= FMODE_OPENED;
    if ((f->f_mode & FMODE_READ) &&
         likely(f->f_op->read || f->f_op->read_iter))
        f->f_mode |= FMODE_CAN_READ;
    if ((f->f_mode & FMODE_WRITE) &&
         likely(f->f_op->write || f->f_op->write_iter))
        f->f_mode |= FMODE_CAN_WRITE;
    if ((f->f_mode & FMODE_LSEEK) && !f->f_op->llseek)
        f->f_mode &= ~FMODE_LSEEK;
    if (f->f_mapping->a_ops && f->f_mapping->a_ops->direct_IO)
        f->f_mode |= FMODE_CAN_ODIRECT;

    f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
    f->f_iocb_flags = iocb_flags(f);

    file_ra_state_init(&f->f_ra, f->f_mapping->host->i_mapping);

    if ((f->f_flags & O_DIRECT) && !(f->f_mode & FMODE_CAN_ODIRECT))
        return -EINVAL;

    /*
     * XXX: Huge page cache doesn't support writing yet. Drop all page
     * cache for this file before processing writes.
     */
    if (f->f_mode & FMODE_WRITE) {
        /*
         * Depends on full fence from get_write_access() to synchronize
         * against collapse_file() regarding i_writecount and nr_thps
         * updates. Ensures subsequent insertion of THPs into the page
         * cache will fail.
         */
        if (filemap_nr_thps(inode->i_mapping)) {
            struct address_space *mapping = inode->i_mapping;

            filemap_invalidate_lock(inode->i_mapping);
            /*
             * unmap_mapping_range just need to be called once
             * here, because the private pages is not need to be
             * unmapped mapping (e.g. data segment of dynamic
             * shared libraries here).
             */
            unmap_mapping_range(mapping, 0, 0, 0);
            truncate_inode_pages(mapping, 0);
            filemap_invalidate_unlock(inode->i_mapping);
        }
    }

    return 0;

cleanup_all:
    if (WARN_ON_ONCE(error > 0))
        error = -EINVAL;
    fops_put(f->f_op);
    put_file_access(f);
cleanup_file:
    path_put(&f->f_path);
    f->f_path.mnt = NULL;
    f->f_path.dentry = NULL;
    f->f_inode = NULL;
    return error;
}

/**
 * vfs_open - open the file at the given path
 * @path: path to open
 * @file: newly allocated file with f_flag initialized
 */
int vfs_open(const struct path *path, struct file *file)
{
    int ret;

    file->f_path = *path;
    ret = do_dentry_open(file, NULL);
    if (!ret) {
        /*
         * Once we return a file with FMODE_OPENED, __fput() will call
         * fsnotify_close(), so we need fsnotify_open() here for
         * symmetry.
         */
        fsnotify_open(file);
    }
    return ret;
}

/*
 * "id" is the POSIX thread ID. We use the
 * files pointer for this..
 */
static int filp_flush(struct file *filp, fl_owner_t id)
{
    int retval = 0;

    if (CHECK_DATA_CORRUPTION(file_count(filp) == 0,
            "VFS: Close: file count is 0 (f_op=%ps)",
            filp->f_op)) {
        return 0;
    }

    if (filp->f_op->flush)
        retval = filp->f_op->flush(filp, id);

    if (likely(!(filp->f_mode & FMODE_PATH))) {
        dnotify_flush(filp, id);
        locks_remove_posix(filp, id);
    }
    return retval;
}

int cl_sys_close(int fd)
{
    int retval;
    struct file *file;

    file = file_close_fd(fd);
    if (!file)
        return -EBADF;

    retval = filp_flush(file, current->files);

    /*
     * We're returning to user space. Don't bother
     * with any delayed fput() cases.
     */
    __fput_sync(file);

    /* can't restart close syscall because file table entry was cleared */
    if (unlikely(retval == -ERESTARTSYS ||
             retval == -ERESTARTNOINTR ||
             retval == -ERESTARTNOHAND ||
             retval == -ERESTART_RESTARTBLOCK))
        retval = -EINTR;

    return retval;
}

/*
 * Called when an inode is about to be open.
 * We use this to disallow opening large files on 32bit systems if
 * the caller didn't specify O_LARGEFILE.  On 64bit systems we force
 * on this flag in sys_open.
 */
int generic_file_open(struct inode * inode, struct file * filp)
{
    if (!(filp->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
        return -EOVERFLOW;
    return 0;
}
