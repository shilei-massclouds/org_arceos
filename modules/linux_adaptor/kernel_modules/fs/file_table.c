#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/eventpoll.h>
#include <linux/rcupdate.h>
#include <linux/mount.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/fsnotify.h>
#include <linux/sysctl.h>
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#include <linux/task_work.h>
#include <linux/swap.h>
#include <linux/kmemleak.h>

#include <linux/atomic.h>

#include "internal.h"

#include "../adaptor.h"

/* SLAB cache for file structures */
static struct kmem_cache *filp_cachep __ro_after_init;

static struct percpu_counter nr_files __cacheline_aligned_in_smp;

/* the real guts of fput() - releasing the last reference to file
 */
static void __fput(struct file *file)
{
    PANIC("");
}

static LLIST_HEAD(delayed_fput_list);
static void delayed_fput(struct work_struct *unused)
{
    struct llist_node *node = llist_del_all(&delayed_fput_list);
    struct file *f, *t;

    llist_for_each_entry_safe(f, t, node, f_llist)
        __fput(f);
}

static DECLARE_DELAYED_WORK(delayed_fput_work, delayed_fput);

/* Container for backing file with optional user path */
struct backing_file {
    struct file file;
    struct path user_path;
};

static inline struct backing_file *backing_file(struct file *f)
{
    return container_of(f, struct backing_file, file);
}

static int init_file(struct file *f, int flags, const struct cred *cred)
{
    int error;

    f->f_cred = get_cred(cred);
#if 0
    error = security_file_alloc(f);
    if (unlikely(error)) {
        put_cred(f->f_cred);
        return error;
    }
#endif

    spin_lock_init(&f->f_lock);
    /*
     * Note that f_pos_lock is only used for files raising
     * FMODE_ATOMIC_POS and directories. Other files such as pipes
     * don't need it and since f_pos_lock is in a union may reuse
     * the space for other purposes. They are expected to initialize
     * the respective member when opening the file.
     */
    mutex_init(&f->f_pos_lock);
    f->f_flags = flags;
    f->f_mode = OPEN_FMODE(flags);
    /* f->f_version: 0 */

    /*
     * We're SLAB_TYPESAFE_BY_RCU so initialize f_count last. While
     * fget-rcu pattern users need to be able to handle spurious
     * refcount bumps we should reinitialize the reused file first.
     */
    atomic_long_set(&f->f_count, 1);
    return 0;
}

static inline int alloc_path_pseudo(const char *name, struct inode *inode,
                    struct vfsmount *mnt, struct path *path)
{
    path->dentry = d_alloc_pseudo(mnt->mnt_sb, &QSTR(name));
    if (!path->dentry)
        return -ENOMEM;
    path->mnt = mntget(mnt);
    d_instantiate(path->dentry, inode);
    return 0;
}

/**
 * file_init_path - initialize a 'struct file' based on path
 *
 * @file: the file to set up
 * @path: the (dentry, vfsmount) pair for the new file
 * @fop: the 'struct file_operations' for the new file
 */
static void file_init_path(struct file *file, const struct path *path,
               const struct file_operations *fop)
{
    file->f_path = *path;
    file->f_inode = path->dentry->d_inode;
    file->f_mapping = path->dentry->d_inode->i_mapping;
    file->f_wb_err = filemap_sample_wb_err(file->f_mapping);
    file->f_sb_err = file_sample_sb_err(file);
    if (fop->llseek)
        file->f_mode |= FMODE_LSEEK;
    if ((file->f_mode & FMODE_READ) &&
         likely(fop->read || fop->read_iter))
        file->f_mode |= FMODE_CAN_READ;
    if ((file->f_mode & FMODE_WRITE) &&
         likely(fop->write || fop->write_iter))
        file->f_mode |= FMODE_CAN_WRITE;
    file->f_iocb_flags = iocb_flags(file);
    file->f_mode |= FMODE_OPENED;
    file->f_op = fop;
    if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
        i_readcount_inc(path->dentry->d_inode);
}

struct file *alloc_file_pseudo_noaccount(struct inode *inode,
                     struct vfsmount *mnt, const char *name,
                     int flags,
                     const struct file_operations *fops)
{
    int ret;
    struct path path;
    struct file *file;

    ret = alloc_path_pseudo(name, inode, mnt, &path);
    if (ret)
        return ERR_PTR(ret);

    file = alloc_empty_file_noaccount(flags, current_cred());
    if (IS_ERR(file)) {
        ihold(inode);
        path_put(&path);
        return file;
    }
    file_init_path(file, &path, fops);
    return file;
}

/*
 * Variant of alloc_empty_file() that doesn't check and modify nr_files.
 *
 * This is only for kernel internal use, and the allocate file must not be
 * installed into file tables or such.
 */
struct file *alloc_empty_file_noaccount(int flags, const struct cred *cred)
{
    struct file *f;
    int error;

    f = kmem_cache_zalloc(filp_cachep, GFP_KERNEL);
    if (unlikely(!f))
        return ERR_PTR(-ENOMEM);

    error = init_file(f, flags, cred);
    if (unlikely(error)) {
        kmem_cache_free(filp_cachep, f);
        return ERR_PTR(error);
    }

    f->f_mode |= FMODE_NOACCOUNT;

    return f;
}

struct path *backing_file_user_path(struct file *f)
{
    return &backing_file(f)->user_path;
}

static inline void file_free(struct file *f)
{
    //security_file_free(f);
    if (likely(!(f->f_mode & FMODE_NOACCOUNT)))
        percpu_counter_dec(&nr_files);
    put_cred(f->f_cred);
    if (unlikely(f->f_mode & FMODE_BACKING)) {
        path_put(backing_file_user_path(f));
        kfree(backing_file(f));
    } else {
        kmem_cache_free(filp_cachep, f);
    }
}

static void ____fput(struct callback_head *work)
{
    __fput(container_of(work, struct file, f_task_work));
}

void fput(struct file *file)
{
    if (atomic_long_dec_and_test(&file->f_count)) {
        struct task_struct *task = current;

        if (unlikely(!(file->f_mode & (FMODE_BACKING | FMODE_OPENED)))) {
            file_free(file);
            return;
        }
        if (likely(!in_interrupt() && !(task->flags & PF_KTHREAD))) {
            init_task_work(&file->f_task_work, ____fput);
            if (!task_work_add(task, &file->f_task_work, TWA_RESUME))
                return;
            /*
             * After this task has run exit_task_work(),
             * task_work_add() will fail.  Fall through to delayed
             * fput to avoid leaking *file.
             */
        }

        if (llist_add(&file->f_llist, &delayed_fput_list))
            schedule_delayed_work(&delayed_fput_work, 1);
    }
}

void __init files_init(void)
{
    struct kmem_cache_args args = {
        .use_freeptr_offset = true,
        .freeptr_offset = offsetof(struct file, f_freeptr),
    };

    filp_cachep = kmem_cache_create("filp", sizeof(struct file), &args,
                SLAB_HWCACHE_ALIGN | SLAB_PANIC |
                SLAB_ACCOUNT | SLAB_TYPESAFE_BY_RCU);
    //percpu_counter_init(&nr_files, 0, GFP_KERNEL);
}

/*
 * One file with associated inode and dcache is very roughly 1K. Per default
 * do not use more than 10% of our memory for files.
 */
void __init files_maxfiles_init(void)
{
#if 0
    unsigned long n;
    unsigned long nr_pages = totalram_pages();
    unsigned long memreserve = (nr_pages - nr_free_pages()) * 3/2;

    memreserve = min(memreserve, nr_pages - 1);
    n = ((nr_pages - memreserve) * (PAGE_SIZE / 1024)) / 10;

    files_stat.max_files = max_t(unsigned long, n, NR_FILE);
#endif
    pr_err("%s: No impl.", __func__);
}
