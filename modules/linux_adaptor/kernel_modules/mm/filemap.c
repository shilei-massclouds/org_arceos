#include <linux/export.h>
#include <linux/compiler.h>
#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/syscalls.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/error-injection.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/shmem_fs.h>
#include <linux/rmap.h>
#include <linux/delayacct.h>
#include <linux/psi.h>
#include <linux/ramfs.h>
#include <linux/page_idle.h>
#include <linux/migrate.h>
#include <linux/pipe_fs_i.h>
#include <linux/splice.h>
#include <linux/rcupdate_wait.h>

#include <linux/sched/mm.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/filemap.h>

/*
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for try_to_free_buffers */

#include <asm/mman.h>

#include "swap.h"

#include "../adaptor.h"

/*
 * A choice of three behaviors for folio_wait_bit_common():
 */
enum behavior {
    EXCLUSIVE,  /* Hold ref to page and take the bit when woken, like
             * __folio_lock() waiting on then setting PG_locked.
             */
    SHARED,     /* Hold ref to page and check the bit when woken, like
             * folio_wait_writeback() waiting on PG_writeback.
             */
    DROP,       /* Drop ref to page before wait, no check when woken,
             * like folio_put_wait_locked() on PG_locked.
             */
};

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
#define PAGE_WAIT_TABLE_BITS 8
#define PAGE_WAIT_TABLE_SIZE (1 << PAGE_WAIT_TABLE_BITS)
static wait_queue_head_t folio_wait_table[PAGE_WAIT_TABLE_SIZE] __cacheline_aligned;

static wait_queue_head_t *folio_waitqueue(struct folio *folio)
{
    return &folio_wait_table[hash_ptr(folio, PAGE_WAIT_TABLE_BITS)];
}

/* Returns true if writeback might be needed or already in progress. */
static bool mapping_needs_writeback(struct address_space *mapping)
{
    return mapping->nrpages;
}

static void mapping_set_update(struct xa_state *xas,
        struct address_space *mapping)
{
    if (dax_mapping(mapping) || shmem_mapping(mapping))
        return;
    xas_set_update(xas, workingset_update_node);
    xas_set_lru(xas, &shadow_nodes);
}

/*
 * CD/DVDs are error prone. When a medium error occurs, the driver may fail
 * a _large_ part of the i/o request. Imagine the worst scenario:
 *
 *      ---R__________________________________________B__________
 *         ^ reading here                             ^ bad block(assume 4k)
 *
 * read(R) => miss => readahead(R...B) => media error => frustrating retries
 * => failing the whole request => read(R) => read(R+1) =>
 * readahead(R+1...B+1) => bang => read(R+2) => read(R+3) =>
 * readahead(R+3...B+2) => bang => read(R+3) => read(R+4) =>
 * readahead(R+4...B+3) => bang => read(R+4) => read(R+5) => ......
 *
 * It is going insane. Fix it by quickly scaling down the readahead size.
 */
static void shrink_readahead_size_eio(struct file_ra_state *ra)
{
    ra->ra_pages /= 4;
}

int filemap_check_errors(struct address_space *mapping)
{
    int ret = 0;
    /* Check for outstanding write errors */
    if (test_bit(AS_ENOSPC, &mapping->flags) &&
        test_and_clear_bit(AS_ENOSPC, &mapping->flags))
        ret = -ENOSPC;
    if (test_bit(AS_EIO, &mapping->flags) &&
        test_and_clear_bit(AS_EIO, &mapping->flags))
        ret = -EIO;
    return ret;
}

/**
 * __filemap_fdatawrite_range - start writeback on mapping dirty pages in range
 * @mapping:    address space structure to write
 * @start:  offset in bytes where the range starts
 * @end:    offset in bytes where the range ends (inclusive)
 * @sync_mode:  enable synchronous operation
 *
 * Start writeback against all of a mapping's dirty pages that lie
 * within the byte offsets <start, end> inclusive.
 *
 * If sync_mode is WB_SYNC_ALL then this is a "data integrity" operation, as
 * opposed to a regular memory cleansing writeback.  The difference between
 * these two operations is that if a dirty page/buffer is encountered, it must
 * be waited upon, and not just skipped over.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int __filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
                loff_t end, int sync_mode)
{
    struct writeback_control wbc = {
        .sync_mode = sync_mode,
        .nr_to_write = LONG_MAX,
        .range_start = start,
        .range_end = end,
    };

    printk("%s: step1 sync_mode(%d)\n", __func__, sync_mode);
    return filemap_fdatawrite_wbc(mapping, &wbc);
}

/**
 * filemap_fdatawrite_wbc - start writeback on mapping dirty pages in range
 * @mapping:    address space structure to write
 * @wbc:    the writeback_control controlling the writeout
 *
 * Call writepages on the mapping using the provided wbc to control the
 * writeout.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int filemap_fdatawrite_wbc(struct address_space *mapping,
               struct writeback_control *wbc)
{
    int ret;

    printk("%s: step0\n", __func__);
    if (!mapping_can_writeback(mapping) ||
        !mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
        return 0;

    printk("%s: step1\n", __func__);
    wbc_attach_fdatawrite_inode(wbc, mapping->host);
    ret = do_writepages(mapping, wbc);
    printk("%s: step2\n", __func__);
    wbc_detach_inode(wbc);
    printk("%s: step3\n", __func__);
    return ret;
}

static void __filemap_fdatawait_range(struct address_space *mapping,
                     loff_t start_byte, loff_t end_byte)
{
    pgoff_t index = start_byte >> PAGE_SHIFT;
    pgoff_t end = end_byte >> PAGE_SHIFT;
    struct folio_batch fbatch;
    unsigned nr_folios;

#if 0
    folio_batch_init(&fbatch);

    while (index <= end) {
        unsigned i;

        nr_folios = filemap_get_folios_tag(mapping, &index, end,
                PAGECACHE_TAG_WRITEBACK, &fbatch);

        if (!nr_folios)
            break;

        for (i = 0; i < nr_folios; i++) {
            struct folio *folio = fbatch.folios[i];

            folio_wait_writeback(folio);
        }
        folio_batch_release(&fbatch);
        cond_resched();
    }
#endif
}

/*
 * Attempt to check (or get) the folio flag, and mark us done
 * if successful.
 */
static inline bool folio_trylock_flag(struct folio *folio, int bit_nr,
                    struct wait_queue_entry *wait)
{
    if (wait->flags & WQ_FLAG_EXCLUSIVE) {
        if (test_and_set_bit(bit_nr, &folio->flags))
            return false;
    } else if (test_bit(bit_nr, &folio->flags))
        return false;

    wait->flags |= WQ_FLAG_WOKEN | WQ_FLAG_DONE;
    return true;
}

/*
 * The page wait code treats the "wait->flags" somewhat unusually, because
 * we have multiple different kinds of waits, not just the usual "exclusive"
 * one.
 *
 * We have:
 *
 *  (a) no special bits set:
 *
 *  We're just waiting for the bit to be released, and when a waker
 *  calls the wakeup function, we set WQ_FLAG_WOKEN and wake it up,
 *  and remove it from the wait queue.
 *
 *  Simple and straightforward.
 *
 *  (b) WQ_FLAG_EXCLUSIVE:
 *
 *  The waiter is waiting to get the lock, and only one waiter should
 *  be woken up to avoid any thundering herd behavior. We'll set the
 *  WQ_FLAG_WOKEN bit, wake it up, and remove it from the wait queue.
 *
 *  This is the traditional exclusive wait.
 *
 *  (c) WQ_FLAG_EXCLUSIVE | WQ_FLAG_CUSTOM:
 *
 *  The waiter is waiting to get the bit, and additionally wants the
 *  lock to be transferred to it for fair lock behavior. If the lock
 *  cannot be taken, we stop walking the wait queue without waking
 *  the waiter.
 *
 *  This is the "fair lock handoff" case, and in addition to setting
 *  WQ_FLAG_WOKEN, we set WQ_FLAG_DONE to let the waiter easily see
 *  that it now has the lock.
 */
static int wake_page_function(wait_queue_entry_t *wait, unsigned mode, int sync, void *arg)
{
    unsigned int flags;
    struct wait_page_key *key = arg;
    struct wait_page_queue *wait_page
        = container_of(wait, struct wait_page_queue, wait);

    if (!wake_page_match(wait_page, key))
        return 0;

    /*
     * If it's a lock handoff wait, we get the bit for it, and
     * stop walking (and do not wake it up) if we can't.
     */
    flags = wait->flags;
    if (flags & WQ_FLAG_EXCLUSIVE) {
        if (test_bit(key->bit_nr, &key->folio->flags))
            return -1;
        if (flags & WQ_FLAG_CUSTOM) {
            if (test_and_set_bit(key->bit_nr, &key->folio->flags))
                return -1;
            flags |= WQ_FLAG_DONE;
        }
    }

    /*
     * We are holding the wait-queue lock, but the waiter that
     * is waiting for this will be checking the flags without
     * any locking.
     *
     * So update the flags atomically, and wake up the waiter
     * afterwards to avoid any races. This store-release pairs
     * with the load-acquire in folio_wait_bit_common().
     */
    smp_store_release(&wait->flags, flags | WQ_FLAG_WOKEN);
    wake_up_state(wait->private, mode);

    /*
     * Ok, we have successfully done what we're waiting for,
     * and we can unconditionally remove the wait entry.
     *
     * Note that this pairs with the "finish_wait()" in the
     * waiter, and has to be the absolute last thing we do.
     * After this list_del_init(&wait->entry) the wait entry
     * might be de-allocated and the process might even have
     * exited.
     */
    list_del_init_careful(&wait->entry);
    return (flags & WQ_FLAG_EXCLUSIVE) != 0;
}

static inline int folio_wait_bit_common(struct folio *folio, int bit_nr,
        int state, enum behavior behavior)
{
    wait_queue_head_t *q = folio_waitqueue(folio);
    int unfairness = sysctl_page_lock_unfairness;
    struct wait_page_queue wait_page;
    wait_queue_entry_t *wait = &wait_page.wait;
    bool thrashing = false;
    unsigned long pflags;
    bool in_thrashing;

    if (bit_nr == PG_locked &&
        !folio_test_uptodate(folio) && folio_test_workingset(folio)) {
        delayacct_thrashing_start(&in_thrashing);
        psi_memstall_enter(&pflags);
        thrashing = true;
    }

    init_wait(wait);
    wait->func = wake_page_function;
    wait_page.folio = folio;
    wait_page.bit_nr = bit_nr;

repeat:
    wait->flags = 0;
    if (behavior == EXCLUSIVE) {
        wait->flags = WQ_FLAG_EXCLUSIVE;
        if (--unfairness < 0)
            wait->flags |= WQ_FLAG_CUSTOM;
    }

    /*
     * Do one last check whether we can get the
     * page bit synchronously.
     *
     * Do the folio_set_waiters() marking before that
     * to let any waker we _just_ missed know they
     * need to wake us up (otherwise they'll never
     * even go to the slow case that looks at the
     * page queue), and add ourselves to the wait
     * queue if we need to sleep.
     *
     * This part needs to be done under the queue
     * lock to avoid races.
     */
    spin_lock_irq(&q->lock);
    folio_set_waiters(folio);
    if (!folio_trylock_flag(folio, bit_nr, wait))
        __add_wait_queue_entry_tail(q, wait);
    spin_unlock_irq(&q->lock);

    /*
     * From now on, all the logic will be based on
     * the WQ_FLAG_WOKEN and WQ_FLAG_DONE flag, to
     * see whether the page bit testing has already
     * been done by the wake function.
     *
     * We can drop our reference to the folio.
     */
    if (behavior == DROP)
        folio_put(folio);

    /*
     * Note that until the "finish_wait()", or until
     * we see the WQ_FLAG_WOKEN flag, we need to
     * be very careful with the 'wait->flags', because
     * we may race with a waker that sets them.
     */
    for (;;) {
        unsigned int flags;

        set_current_state(state);

        /* Loop until we've been woken or interrupted */
        flags = smp_load_acquire(&wait->flags);
        if (!(flags & WQ_FLAG_WOKEN)) {
            if (signal_pending_state(state, current))
                break;

            io_schedule();
            continue;
        }

        /* If we were non-exclusive, we're done */
        if (behavior != EXCLUSIVE)
            break;

        /* If the waker got the lock for us, we're done */
        if (flags & WQ_FLAG_DONE)
            break;

        /*
         * Otherwise, if we're getting the lock, we need to
         * try to get it ourselves.
         *
         * And if that fails, we'll have to retry this all.
         */
        if (unlikely(test_and_set_bit(bit_nr, folio_flags(folio, 0))))
            goto repeat;

        wait->flags |= WQ_FLAG_DONE;
        break;
    }

    /*
     * If a signal happened, this 'finish_wait()' may remove the last
     * waiter from the wait-queues, but the folio waiters bit will remain
     * set. That's ok. The next wakeup will take care of it, and trying
     * to do it here would be difficult and prone to races.
     */
    finish_wait(q, wait);

    if (thrashing) {
        delayacct_thrashing_end(&in_thrashing);
        psi_memstall_leave(&pflags);
    }

    /*
     * NOTE! The wait->flags weren't stable until we've done the
     * 'finish_wait()', and we could have exited the loop above due
     * to a signal, and had a wakeup event happen after the signal
     * test but before the 'finish_wait()'.
     *
     * So only after the finish_wait() can we reliably determine
     * if we got woken up or not, so we can now figure out the final
     * return value based on that state without races.
     *
     * Also note that WQ_FLAG_WOKEN is sufficient for a non-exclusive
     * waiter, but an exclusive one requires WQ_FLAG_DONE.
     */
    if (behavior == EXCLUSIVE)
        return wait->flags & WQ_FLAG_DONE ? 0 : -EINTR;

    return wait->flags & WQ_FLAG_WOKEN ? 0 : -EINTR;
}

int folio_wait_bit_killable(struct folio *folio, int bit_nr)
{
    return folio_wait_bit_common(folio, bit_nr, TASK_KILLABLE, SHARED);
}

static void folio_wake_bit(struct folio *folio, int bit_nr)
{
    wait_queue_head_t *q = folio_waitqueue(folio);
    struct wait_page_key key;
    unsigned long flags;

    key.folio = folio;
    key.bit_nr = bit_nr;
    key.page_match = 0;

    spin_lock_irqsave(&q->lock, flags);
    __wake_up_locked_key(q, TASK_NORMAL, &key);

    /*
     * It's possible to miss clearing waiters here, when we woke our page
     * waiters, but the hashed waitqueue has waiters for other pages on it.
     * That's okay, it's a rare case. The next waker will clear it.
     *
     * Note that, depending on the page pool (buddy, hugetlb, ZONE_DEVICE,
     * other), the flag may be cleared in the course of freeing the page;
     * but that is not required for correctness.
     */
    if (!waitqueue_active(q) || !key.page_match)
        folio_clear_waiters(folio);

    spin_unlock_irqrestore(&q->lock, flags);
}

/**
 * folio_end_read - End read on a folio.
 * @folio: The folio.
 * @success: True if all reads completed successfully.
 *
 * When all reads against a folio have completed, filesystems should
 * call this function to let the pagecache know that no more reads
 * are outstanding.  This will unlock the folio and wake up any thread
 * sleeping on the lock.  The folio will also be marked uptodate if all
 * reads succeeded.
 *
 * Context: May be called from interrupt or process context.  May not be
 * called from NMI context.
 */
void folio_end_read(struct folio *folio, bool success)
{
    unsigned long mask = 1 << PG_locked;

    /* Must be in bottom byte for x86 to work */
    BUILD_BUG_ON(PG_uptodate > 7);
    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
    VM_BUG_ON_FOLIO(folio_test_uptodate(folio), folio);

    if (likely(success))
        mask |= 1 << PG_uptodate;
    if (folio_xor_flags_has_waiters(folio, mask))
        folio_wake_bit(folio, PG_locked);
}

/**
 * filemap_write_and_wait_range - write out & wait on a file range
 * @mapping:    the address_space for the pages
 * @lstart: offset in bytes where the range starts
 * @lend:   offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that @lend is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 *
 * Return: error status of the address space.
 */
int filemap_write_and_wait_range(struct address_space *mapping,
                 loff_t lstart, loff_t lend)
{
    int err = 0, err2;

    if (lend < lstart)
        return 0;

    if (mapping_needs_writeback(mapping)) {
        err = __filemap_fdatawrite_range(mapping, lstart, lend,
                         WB_SYNC_ALL);
        /*
         * Even if the above returned error, the pages may be
         * written partially (e.g. -ENOSPC), so we wait for it.
         * But the -EIO is special case, it may indicate the worst
         * thing (e.g. bug) happened, so we avoid waiting for it.
         */
        if (err != -EIO)
            __filemap_fdatawait_range(mapping, lstart, lend);
    }
    err2 = filemap_check_errors(mapping);
    if (!err)
        err = err2;
    return err;
}

/**
 * __filemap_get_folio - Find and get a reference to a folio.
 * @mapping: The address_space to search.
 * @index: The page index.
 * @fgp_flags: %FGP flags modify how the folio is returned.
 * @gfp: Memory allocation flags to use if %FGP_CREAT is specified.
 *
 * Looks up the page cache entry at @mapping & @index.
 *
 * If %FGP_LOCK or %FGP_CREAT are specified then the function may sleep even
 * if the %GFP flags specified for %FGP_CREAT are atomic.
 *
 * If this function returns a folio, it is returned with an increased refcount.
 *
 * Return: The found folio or an ERR_PTR() otherwise.
 */
struct folio *__filemap_get_folio(struct address_space *mapping, pgoff_t index,
        fgf_t fgp_flags, gfp_t gfp)
{
    struct folio *folio;

repeat:
    folio = filemap_get_entry(mapping, index);
    if (xa_is_value(folio))
        folio = NULL;
    if (!folio)
        goto no_page;

    if (fgp_flags & FGP_LOCK) {
        if (fgp_flags & FGP_NOWAIT) {
            if (!folio_trylock(folio)) {
                folio_put(folio);
                return ERR_PTR(-EAGAIN);
            }
        } else {
            folio_lock(folio);
        }

        /* Has the page been truncated? */
        if (unlikely(folio->mapping != mapping)) {
            folio_unlock(folio);
            folio_put(folio);
            goto repeat;
        }
        VM_BUG_ON_FOLIO(!folio_contains(folio, index), folio);
    }

    if (fgp_flags & FGP_ACCESSED)
        folio_mark_accessed(folio);
    else if (fgp_flags & FGP_WRITE) {
        /* Clear idle flag for buffer write */
        if (folio_test_idle(folio))
            folio_clear_idle(folio);
    }

    if (fgp_flags & FGP_STABLE)
        folio_wait_stable(folio);
no_page:
    if (!folio && (fgp_flags & FGP_CREAT)) {
        unsigned int min_order = mapping_min_folio_order(mapping);
        unsigned int order = max(min_order, FGF_GET_ORDER(fgp_flags));
        int err;
        index = mapping_align_index(mapping, index);

        if ((fgp_flags & FGP_WRITE) && mapping_can_writeback(mapping))
            gfp |= __GFP_WRITE;
        if (fgp_flags & FGP_NOFS)
            gfp &= ~__GFP_FS;
        if (fgp_flags & FGP_NOWAIT) {
            gfp &= ~GFP_KERNEL;
            gfp |= GFP_NOWAIT | __GFP_NOWARN;
        }
        if (WARN_ON_ONCE(!(fgp_flags & (FGP_LOCK | FGP_FOR_MMAP))))
            fgp_flags |= FGP_LOCK;

        if (order > mapping_max_folio_order(mapping))
            order = mapping_max_folio_order(mapping);
        /* If we're not aligned, allocate a smaller folio */
        if (index & ((1UL << order) - 1))
            order = __ffs(index);

        do {
            gfp_t alloc_gfp = gfp;

            err = -ENOMEM;
            if (order > min_order)
                alloc_gfp |= __GFP_NORETRY | __GFP_NOWARN;
            folio = filemap_alloc_folio(alloc_gfp, order);
            if (!folio)
                continue;

            /* Init accessed so avoid atomic mark_page_accessed later */
            if (fgp_flags & FGP_ACCESSED)
                __folio_set_referenced(folio);

            err = filemap_add_folio(mapping, folio, index, gfp);
            if (!err)
                break;
            folio_put(folio);
            folio = NULL;
        } while (order-- > min_order);

        if (err == -EEXIST)
            goto repeat;
        if (err) {
            /*
             * When NOWAIT I/O fails to allocate folios this could
             * be due to a nonblocking memory allocation and not
             * because the system actually is out of memory.
             * Return -EAGAIN so that there caller retries in a
             * blocking fashion instead of propagating -ENOMEM
             * to the application.
             */
            if ((fgp_flags & FGP_NOWAIT) && err == -ENOMEM)
                err = -EAGAIN;
            return ERR_PTR(err);
        }
        /*
         * filemap_add_folio locks the page, and for mmap
         * we expect an unlocked page.
         */
        if (folio && (fgp_flags & FGP_FOR_MMAP))
            folio_unlock(folio);
    }

    if (!folio)
        return ERR_PTR(-ENOENT);
    return folio;
}

int filemap_add_folio(struct address_space *mapping, struct folio *folio,
                pgoff_t index, gfp_t gfp)
{
    void *shadow = NULL;
    int ret;

#if 0
    ret = mem_cgroup_charge(folio, NULL, gfp);
    if (ret)
        return ret;
#endif

    __folio_set_locked(folio);
    ret = __filemap_add_folio(mapping, folio, index, gfp, &shadow);
    if (unlikely(ret)) {
        mem_cgroup_uncharge(folio);
        __folio_clear_locked(folio);
    } else {
        /*
         * The folio might have been evicted from cache only
         * recently, in which case it should be activated like
         * any other repeatedly accessed folio.
         * The exception is folios getting rewritten; evicting other
         * data from the working set, only to cache data that will
         * get overwritten with something else, is a waste of memory.
         */
        WARN_ON_ONCE(folio_test_active(folio));
        if (!(gfp & __GFP_WRITE) && shadow)
            workingset_refault(folio, shadow);
        folio_add_lru(folio);
    }
    return ret;
}

noinline int __filemap_add_folio(struct address_space *mapping,
        struct folio *folio, pgoff_t index, gfp_t gfp, void **shadowp)
{
    XA_STATE(xas, &mapping->i_pages, index);
    void *alloced_shadow = NULL;
    int alloced_order = 0;
    bool huge;
    long nr;

    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
    VM_BUG_ON_FOLIO(folio_test_swapbacked(folio), folio);
    VM_BUG_ON_FOLIO(folio_order(folio) < mapping_min_folio_order(mapping),
            folio);
    mapping_set_update(&xas, mapping);

    VM_BUG_ON_FOLIO(index & (folio_nr_pages(folio) - 1), folio);
    xas_set_order(&xas, index, folio_order(folio));
    huge = folio_test_hugetlb(folio);
    nr = folio_nr_pages(folio);

    gfp &= GFP_RECLAIM_MASK;
    folio_ref_add(folio, nr);
    folio->mapping = mapping;
    folio->index = xas.xa_index;

    for (;;) {
        int order = -1, split_order = 0;
        void *entry, *old = NULL;

        xas_lock_irq(&xas);
        xas_for_each_conflict(&xas, entry) {
            old = entry;
            if (!xa_is_value(entry)) {
                xas_set_err(&xas, -EEXIST);
                goto unlock;
            }
            /*
             * If a larger entry exists,
             * it will be the first and only entry iterated.
             */
            if (order == -1)
                order = xas_get_order(&xas);
        }

        /* entry may have changed before we re-acquire the lock */
        if (alloced_order && (old != alloced_shadow || order != alloced_order)) {
            xas_destroy(&xas);
            alloced_order = 0;
        }

        if (old) {
            if (order > 0 && order > folio_order(folio)) {
                /* How to handle large swap entries? */
                BUG_ON(shmem_mapping(mapping));
                if (!alloced_order) {
                    split_order = order;
                    goto unlock;
                }
                xas_split(&xas, old, order);
                xas_reset(&xas);
            }
            if (shadowp)
                *shadowp = old;
        }

        xas_store(&xas, folio);
        if (xas_error(&xas))
            goto unlock;

        mapping->nrpages += nr;

#if 0
        /* hugetlb pages do not participate in page cache accounting */
        if (!huge) {
            __lruvec_stat_mod_folio(folio, NR_FILE_PAGES, nr);
            if (folio_test_pmd_mappable(folio))
                __lruvec_stat_mod_folio(folio,
                        NR_FILE_THPS, nr);
        }
#endif

unlock:
        xas_unlock_irq(&xas);

        /* split needed, alloc here and retry. */
        if (split_order) {
            xas_split_alloc(&xas, old, split_order, gfp);
            if (xas_error(&xas))
                goto error;
            alloced_shadow = old;
            alloced_order = split_order;
            xas_reset(&xas);
            continue;
        }

        if (!xas_nomem(&xas, gfp))
            break;
    }

    if (xas_error(&xas))
        goto error;

    trace_mm_filemap_add_to_page_cache(folio);
    return 0;
error:
    folio->mapping = NULL;
    /* Leave page->index set: truncation relies upon it */
    folio_put_refs(folio, nr);
    return xas_error(&xas);
}

/*
 * filemap_get_entry - Get a page cache entry.
 * @mapping: the address_space to search
 * @index: The page cache index.
 *
 * Looks up the page cache entry at @mapping & @index.  If it is a folio,
 * it is returned with an increased refcount.  If it is a shadow entry
 * of a previously evicted folio, or a swap entry from shmem/tmpfs,
 * it is returned without further action.
 *
 * Return: The folio, swap or shadow entry, %NULL if nothing is found.
 */
void *filemap_get_entry(struct address_space *mapping, pgoff_t index)
{
    XA_STATE(xas, &mapping->i_pages, index);
    struct folio *folio;

    rcu_read_lock();
repeat:
    xas_reset(&xas);
    folio = xas_load(&xas);
    if (xas_retry(&xas, folio))
        goto repeat;
    /*
     * A shadow entry of a recently evicted page, or a swap entry from
     * shmem/tmpfs.  Return it without attempting to raise page count.
     */
    if (!folio || xa_is_value(folio))
        goto out;

    if (!folio_try_get(folio))
        goto repeat;

    if (unlikely(folio != xas_reload(&xas))) {
        folio_put(folio);
        goto repeat;
    }
out:
    rcu_read_unlock();

    return folio;
}

/**
 * filemap_get_folios - Get a batch of folios
 * @mapping:    The address_space to search
 * @start:  The starting page index
 * @end:    The final page index (inclusive)
 * @fbatch: The batch to fill.
 *
 * Search for and return a batch of folios in the mapping starting at
 * index @start and up to index @end (inclusive).  The folios are returned
 * in @fbatch with an elevated reference count.
 *
 * Return: The number of folios which were found.
 * We also update @start to index the next folio for the traversal.
 */
unsigned filemap_get_folios(struct address_space *mapping, pgoff_t *start,
        pgoff_t end, struct folio_batch *fbatch)
{
    return filemap_get_folios_tag(mapping, start, end, XA_PRESENT, fbatch);
}

/**
 * folio_unlock - Unlock a locked folio.
 * @folio: The folio.
 *
 * Unlocks the folio and wakes up any thread sleeping on the page lock.
 *
 * Context: May be called from interrupt or process context.  May not be
 * called from NMI context.
 */
void folio_unlock(struct folio *folio)
{
    /* Bit 7 allows x86 to check the byte's sign bit */
    BUILD_BUG_ON(PG_waiters != 7);
    BUILD_BUG_ON(PG_locked > 7);
    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
    if (folio_xor_flags_has_waiters(folio, 1 << PG_locked))
        folio_wake_bit(folio, PG_locked);
}

static inline struct folio *find_get_entry(struct xa_state *xas, pgoff_t max,
        xa_mark_t mark)
{
    struct folio *folio;

retry:
    if (mark == XA_PRESENT)
        folio = xas_find(xas, max);
    else
        folio = xas_find_marked(xas, max, mark);

    if (xas_retry(xas, folio))
        goto retry;
    /*
     * A shadow entry of a recently evicted page, a swap
     * entry from shmem/tmpfs or a DAX entry.  Return it
     * without attempting to raise page count.
     */
    if (!folio || xa_is_value(folio))
        return folio;

    if (!folio_try_get(folio))
        goto reset;

    if (unlikely(folio != xas_reload(xas))) {
        folio_put(folio);
        goto reset;
    }

    return folio;
reset:
    xas_reset(xas);
    goto retry;
}

/**
 * find_lock_entries - Find a batch of pagecache entries.
 * @mapping:    The address_space to search.
 * @start:  The starting page cache index.
 * @end:    The final page index (inclusive).
 * @fbatch: Where the resulting entries are placed.
 * @indices:    The cache indices of the entries in @fbatch.
 *
 * find_lock_entries() will return a batch of entries from @mapping.
 * Swap, shadow and DAX entries are included.  Folios are returned
 * locked and with an incremented refcount.  Folios which are locked
 * by somebody else or under writeback are skipped.  Folios which are
 * partially outside the range are not returned.
 *
 * The entries have ascending indexes.  The indices may not be consecutive
 * due to not-present entries, large folios, folios which could not be
 * locked or folios under writeback.
 *
 * Return: The number of entries which were found.
 */
unsigned find_lock_entries(struct address_space *mapping, pgoff_t *start,
        pgoff_t end, struct folio_batch *fbatch, pgoff_t *indices)
{
    XA_STATE(xas, &mapping->i_pages, *start);
    struct folio *folio;

    rcu_read_lock();
    while ((folio = find_get_entry(&xas, end, XA_PRESENT))) {
        unsigned long base;
        unsigned long nr;

        if (!xa_is_value(folio)) {
            nr = folio_nr_pages(folio);
            base = folio->index;
            /* Omit large folio which begins before the start */
            if (base < *start)
                goto put;
            /* Omit large folio which extends beyond the end */
            if (base + nr - 1 > end)
                goto put;
            if (!folio_trylock(folio))
                goto put;
            if (folio->mapping != mapping ||
                folio_test_writeback(folio))
                goto unlock;
            VM_BUG_ON_FOLIO(!folio_contains(folio, xas.xa_index),
                    folio);
        } else {
            nr = 1 << xas_get_order(&xas);
            base = xas.xa_index & ~(nr - 1);
            /* Omit order>0 value which begins before the start */
            if (base < *start)
                continue;
            /* Omit order>0 value which extends beyond the end */
            if (base + nr - 1 > end)
                break;
        }

        /* Update start now so that last update is correct on return */
        *start = base + nr;
        indices[fbatch->nr] = xas.xa_index;
        if (!folio_batch_add(fbatch, folio))
            break;
        continue;
unlock:
        folio_unlock(folio);
put:
        folio_put(folio);
    }
    rcu_read_unlock();

    return folio_batch_count(fbatch);
}

/**
 * filemap_release_folio() - Release fs-specific metadata on a folio.
 * @folio: The folio which the kernel is trying to free.
 * @gfp: Memory allocation flags (and I/O mode).
 *
 * The address_space is trying to release any data attached to a folio
 * (presumably at folio->private).
 *
 * This will also be called if the private_2 flag is set on a page,
 * indicating that the folio has other metadata associated with it.
 *
 * The @gfp argument specifies whether I/O may be performed to release
 * this page (__GFP_IO), and whether the call may block
 * (__GFP_RECLAIM & __GFP_FS).
 *
 * Return: %true if the release was successful, otherwise %false.
 */
bool filemap_release_folio(struct folio *folio, gfp_t gfp)
{
    struct address_space * const mapping = folio->mapping;

    BUG_ON(!folio_test_locked(folio));
    if (!folio_needs_release(folio))
        return true;
    if (folio_test_writeback(folio))
        return false;

    if (mapping && mapping->a_ops->release_folio)
        return mapping->a_ops->release_folio(folio, gfp);
    return try_to_free_buffers(folio);
}

static void filemap_unaccount_folio(struct address_space *mapping,
        struct folio *folio)
{
    pr_err("%s: No impl.", __func__);
}

/*
 * page_cache_delete_batch - delete several folios from page cache
 * @mapping: the mapping to which folios belong
 * @fbatch: batch of folios to delete
 *
 * The function walks over mapping->i_pages and removes folios passed in
 * @fbatch from the mapping. The function expects @fbatch to be sorted
 * by page index and is optimised for it to be dense.
 * It tolerates holes in @fbatch (mapping entries at those indices are not
 * modified).
 *
 * The function expects the i_pages lock to be held.
 */
static void page_cache_delete_batch(struct address_space *mapping,
                 struct folio_batch *fbatch)
{
    XA_STATE(xas, &mapping->i_pages, fbatch->folios[0]->index);
    long total_pages = 0;
    int i = 0;
    struct folio *folio;

    mapping_set_update(&xas, mapping);
    xas_for_each(&xas, folio, ULONG_MAX) {
        if (i >= folio_batch_count(fbatch))
            break;

        /* A swap/dax/shadow entry got inserted? Skip it. */
        if (xa_is_value(folio))
            continue;
        /*
         * A page got inserted in our range? Skip it. We have our
         * pages locked so they are protected from being removed.
         * If we see a page whose index is higher than ours, it
         * means our page has been removed, which shouldn't be
         * possible because we're holding the PageLock.
         */
        if (folio != fbatch->folios[i]) {
            VM_BUG_ON_FOLIO(folio->index >
                    fbatch->folios[i]->index, folio);
            continue;
        }

        WARN_ON_ONCE(!folio_test_locked(folio));

        folio->mapping = NULL;
        /* Leave folio->index set: truncation lookup relies on it */

        i++;
        xas_store(&xas, NULL);
        total_pages += folio_nr_pages(folio);
    }
    mapping->nrpages -= total_pages;
}

void filemap_free_folio(struct address_space *mapping, struct folio *folio)
{
    void (*free_folio)(struct folio *);
    int refs = 1;

    free_folio = mapping->a_ops->free_folio;
    if (free_folio)
        free_folio(folio);

    if (folio_test_large(folio))
        refs = folio_nr_pages(folio);
    folio_put_refs(folio, refs);
}

void delete_from_page_cache_batch(struct address_space *mapping,
                  struct folio_batch *fbatch)
{
    int i;

    if (!folio_batch_count(fbatch))
        return;

    spin_lock(&mapping->host->i_lock);
    xa_lock_irq(&mapping->i_pages);
    for (i = 0; i < folio_batch_count(fbatch); i++) {
        struct folio *folio = fbatch->folios[i];

        trace_mm_filemap_delete_from_page_cache(folio);
        filemap_unaccount_folio(mapping, folio);
    }
    page_cache_delete_batch(mapping, fbatch);
    xa_unlock_irq(&mapping->i_pages);
    if (mapping_shrinkable(mapping))
        inode_add_lru(mapping->host);
    spin_unlock(&mapping->host->i_lock);

    for (i = 0; i < folio_batch_count(fbatch); i++)
        filemap_free_folio(mapping, fbatch->folios[i]);
}

/**
 * find_get_entries - gang pagecache lookup
 * @mapping:    The address_space to search
 * @start:  The starting page cache index
 * @end:    The final page index (inclusive).
 * @fbatch: Where the resulting entries are placed.
 * @indices:    The cache indices corresponding to the entries in @entries
 *
 * find_get_entries() will search for and return a batch of entries in
 * the mapping.  The entries are placed in @fbatch.  find_get_entries()
 * takes a reference on any actual folios it returns.
 *
 * The entries have ascending indexes.  The indices may not be consecutive
 * due to not-present entries or large folios.
 *
 * Any shadow entries of evicted folios, or swap entries from
 * shmem/tmpfs, are included in the returned array.
 *
 * Return: The number of entries which were found.
 */
unsigned find_get_entries(struct address_space *mapping, pgoff_t *start,
        pgoff_t end, struct folio_batch *fbatch, pgoff_t *indices)
{
    XA_STATE(xas, &mapping->i_pages, *start);
    struct folio *folio;

    rcu_read_lock();
    while ((folio = find_get_entry(&xas, end, XA_PRESENT)) != NULL) {
        indices[fbatch->nr] = xas.xa_index;
        if (!folio_batch_add(fbatch, folio))
            break;
    }

    if (folio_batch_count(fbatch)) {
        unsigned long nr;
        int idx = folio_batch_count(fbatch) - 1;

        folio = fbatch->folios[idx];
        if (!xa_is_value(folio))
            nr = folio_nr_pages(folio);
        else
            nr = 1 << xa_get_order(&mapping->i_pages, indices[idx]);
        *start = round_down(indices[idx] + nr, nr);
    }
    rcu_read_unlock();

    return folio_batch_count(fbatch);
}

/**
 * generic_file_read_iter - generic filesystem read routine
 * @iocb:   kernel I/O control block
 * @iter:   destination for the data read
 *
 * This is the "read_iter()" routine for all filesystems
 * that can use the page cache directly.
 *
 * The IOCB_NOWAIT flag in iocb->ki_flags indicates that -EAGAIN shall
 * be returned when no data can be read without waiting for I/O requests
 * to complete; it doesn't prevent readahead.
 *
 * The IOCB_NOIO flag in iocb->ki_flags indicates that no new I/O
 * requests shall be made for the read or for readahead.  When no data
 * can be read, -EAGAIN shall be returned.  When readahead would be
 * triggered, a partial, possibly empty read shall be returned.
 *
 * Return:
 * * number of bytes copied, even for partial reads
 * * negative error code (or 0 if IOCB_NOIO) if nothing was read
 */
ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    size_t count = iov_iter_count(iter);
    ssize_t retval = 0;

    printk("%s: step1\n", __func__);
    if (!count)
        return 0; /* skip atime */

    if (iocb->ki_flags & IOCB_DIRECT) {
        PANIC("IOCB_DIRECT");
    }

    return filemap_read(iocb, iter, retval);
}

static int filemap_read_folio(struct file *file, filler_t filler,
        struct folio *folio)
{
    bool workingset = folio_test_workingset(folio);
    unsigned long pflags;
    int error;

    /* Start the actual read. The read will unlock the page. */
    if (unlikely(workingset))
        psi_memstall_enter(&pflags);
    error = filler(file, folio);
    if (unlikely(workingset))
        psi_memstall_leave(&pflags);
    if (error)
        return error;

    error = folio_wait_locked_killable(folio);
    if (error)
        return error;
    if (folio_test_uptodate(folio))
        return 0;
    if (file)
        shrink_readahead_size_eio(&file->f_ra);
    return -EIO;
}

/*
 * filemap_get_read_batch - Get a batch of folios for read
 *
 * Get a batch of folios which represent a contiguous range of bytes in
 * the file.  No exceptional entries will be returned.  If @index is in
 * the middle of a folio, the entire folio will be returned.  The last
 * folio in the batch may have the readahead flag set or the uptodate flag
 * clear so that the caller can take the appropriate action.
 */
static void filemap_get_read_batch(struct address_space *mapping,
        pgoff_t index, pgoff_t max, struct folio_batch *fbatch)
{
    XA_STATE(xas, &mapping->i_pages, index);
    struct folio *folio;

    rcu_read_lock();
    for (folio = xas_load(&xas); folio; folio = xas_next(&xas)) {
        if (xas_retry(&xas, folio))
            continue;
        if (xas.xa_index > max || xa_is_value(folio))
            break;
        if (xa_is_sibling(folio))
            break;
        if (!folio_try_get(folio))
            goto retry;

        if (unlikely(folio != xas_reload(&xas)))
            goto put_folio;

        if (!folio_batch_add(fbatch, folio))
            break;
        if (!folio_test_uptodate(folio))
            break;
        if (folio_test_readahead(folio))
            break;
        xas_advance(&xas, folio_next_index(folio) - 1);
        continue;
put_folio:
        folio_put(folio);
retry:
        xas_reset(&xas);
    }
    rcu_read_unlock();
}

static int filemap_create_folio(struct file *file,
        struct address_space *mapping, loff_t pos,
        struct folio_batch *fbatch)
{
    struct folio *folio;
    int error;
    unsigned int min_order = mapping_min_folio_order(mapping);
    pgoff_t index;

    folio = filemap_alloc_folio(mapping_gfp_mask(mapping), min_order);
    if (!folio)
        return -ENOMEM;
    /*
     * Protect against truncate / hole punch. Grabbing invalidate_lock
     * here assures we cannot instantiate and bring uptodate new
     * pagecache folios after evicting page cache during truncate
     * and before actually freeing blocks.  Note that we could
     * release invalidate_lock after inserting the folio into
     * the page cache as the locked folio would then be enough to
     * synchronize with hole punching. But there are code paths
     * such as filemap_update_page() filling in partially uptodate
     * pages or ->readahead() that need to hold invalidate_lock
     * while mapping blocks for IO so let's hold the lock here as
     * well to keep locking rules simple.
     */
    filemap_invalidate_lock_shared(mapping);
    index = (pos >> (PAGE_SHIFT + min_order)) << min_order;
    error = filemap_add_folio(mapping, folio, index,
            mapping_gfp_constraint(mapping, GFP_KERNEL));
    if (error == -EEXIST)
        error = AOP_TRUNCATED_PAGE;
    if (error)
        goto error;

    error = filemap_read_folio(file, mapping->a_ops->read_folio, folio);
    if (error)
        goto error;

    filemap_invalidate_unlock_shared(mapping);
    folio_batch_add(fbatch, folio);
    return 0;
error:
    filemap_invalidate_unlock_shared(mapping);
    folio_put(folio);
    return error;
}

static int filemap_get_pages(struct kiocb *iocb, size_t count,
        struct folio_batch *fbatch, bool need_uptodate)
{
    struct file *filp = iocb->ki_filp;
    struct address_space *mapping = filp->f_mapping;
    struct file_ra_state *ra = &filp->f_ra;
    pgoff_t index = iocb->ki_pos >> PAGE_SHIFT;
    pgoff_t last_index;
    struct folio *folio;
    unsigned int flags;
    int err = 0;

    /* "last_index" is the index of the page beyond the end of the read */
    last_index = DIV_ROUND_UP(iocb->ki_pos + count, PAGE_SIZE);
retry:
    if (fatal_signal_pending(current))
        return -EINTR;

    filemap_get_read_batch(mapping, index, last_index - 1, fbatch);
    if (!folio_batch_count(fbatch)) {
        if (iocb->ki_flags & IOCB_NOIO)
            return -EAGAIN;
        if (iocb->ki_flags & IOCB_NOWAIT)
            flags = memalloc_noio_save();
        page_cache_sync_readahead(mapping, ra, filp, index,
                last_index - index);
        if (iocb->ki_flags & IOCB_NOWAIT)
            memalloc_noio_restore(flags);
        filemap_get_read_batch(mapping, index, last_index - 1, fbatch);
    }
    if (!folio_batch_count(fbatch)) {
        if (iocb->ki_flags & (IOCB_NOWAIT | IOCB_WAITQ))
            return -EAGAIN;
        err = filemap_create_folio(filp, mapping, iocb->ki_pos, fbatch);
        if (err == AOP_TRUNCATED_PAGE)
            goto retry;
        return err;
    }

#if 0
    folio = fbatch->folios[folio_batch_count(fbatch) - 1];
    if (folio_test_readahead(folio)) {
        err = filemap_readahead(iocb, filp, mapping, folio, last_index);
        if (err)
            goto err;
    }
    if (!folio_test_uptodate(folio)) {
        if ((iocb->ki_flags & IOCB_WAITQ) &&
            folio_batch_count(fbatch) > 1)
            iocb->ki_flags |= IOCB_NOWAIT;
        err = filemap_update_page(iocb, mapping, count, folio,
                      need_uptodate);
        if (err)
            goto err;
    }

    trace_mm_filemap_get_pages(mapping, index, last_index - 1);
#endif
    PANIC("");
    return 0;
err:
    PANIC("ERR");
    if (err < 0)
        folio_put(folio);
    if (likely(--fbatch->nr))
        return 0;
    if (err == AOP_TRUNCATED_PAGE)
        goto retry;
    return err;
}

static inline bool pos_same_folio(loff_t pos1, loff_t pos2, struct folio *folio)
{
    unsigned int shift = folio_shift(folio);

    return (pos1 >> shift == pos2 >> shift);
}

/**
 * filemap_read - Read data from the page cache.
 * @iocb: The iocb to read.
 * @iter: Destination for the data.
 * @already_read: Number of bytes already read by the caller.
 *
 * Copies data from the page cache.  If the data is not currently present,
 * uses the readahead and read_folio address_space operations to fetch it.
 *
 * Return: Total number of bytes copied, including those already read by
 * the caller.  If an error happens before any bytes are copied, returns
 * a negative error number.
 */
ssize_t filemap_read(struct kiocb *iocb, struct iov_iter *iter,
        ssize_t already_read)
{
    struct file *filp = iocb->ki_filp;
    struct file_ra_state *ra = &filp->f_ra;
    struct address_space *mapping = filp->f_mapping;
    struct inode *inode = mapping->host;
    struct folio_batch fbatch;
    int i, error = 0;
    bool writably_mapped;
    loff_t isize, end_offset;
    loff_t last_pos = ra->prev_pos;

    printk("%s: step1\n", __func__);
    if (unlikely(iocb->ki_pos >= inode->i_sb->s_maxbytes))
        return 0;
    if (unlikely(!iov_iter_count(iter)))
        return 0;

    iov_iter_truncate(iter, inode->i_sb->s_maxbytes - iocb->ki_pos);
    folio_batch_init(&fbatch);

    do {
        cond_resched();

        /*
         * If we've already successfully copied some data, then we
         * can no longer safely return -EIOCBQUEUED. Hence mark
         * an async read NOWAIT at that point.
         */
        if ((iocb->ki_flags & IOCB_WAITQ) && already_read)
            iocb->ki_flags |= IOCB_NOWAIT;

        if (unlikely(iocb->ki_pos >= i_size_read(inode)))
            break;

        error = filemap_get_pages(iocb, iter->count, &fbatch, false);
        if (error < 0)
            break;

        /*
         * i_size must be checked after we know the pages are Uptodate.
         *
         * Checking i_size after the check allows us to calculate
         * the correct value for "nr", which means the zero-filled
         * part of the page is not copied back to userspace (unless
         * another truncate extends the file - this is desired though).
         */
        isize = i_size_read(inode);
        if (unlikely(iocb->ki_pos >= isize))
            goto put_folios;
        end_offset = min_t(loff_t, isize, iocb->ki_pos + iter->count);

        /*
         * Once we start copying data, we don't want to be touching any
         * cachelines that might be contended:
         */
        writably_mapped = mapping_writably_mapped(mapping);

        /*
         * When a read accesses the same folio several times, only
         * mark it as accessed the first time.
         */
        if (!pos_same_folio(iocb->ki_pos, last_pos - 1,
                    fbatch.folios[0]))
            folio_mark_accessed(fbatch.folios[0]);

        for (i = 0; i < folio_batch_count(&fbatch); i++) {
            struct folio *folio = fbatch.folios[i];
            size_t fsize = folio_size(folio);
            size_t offset = iocb->ki_pos & (fsize - 1);
            size_t bytes = min_t(loff_t, end_offset - iocb->ki_pos,
                         fsize - offset);
            size_t copied;

            if (end_offset < folio_pos(folio))
                break;
            if (i > 0)
                folio_mark_accessed(folio);
            /*
             * If users can be writing to this folio using arbitrary
             * virtual addresses, take care of potential aliasing
             * before reading the folio on the kernel side.
             */
            if (writably_mapped)
                flush_dcache_folio(folio);

    printk("%s: step2 bytes(%u)\n", __func__, bytes);
            copied = copy_folio_to_iter(folio, offset, bytes, iter);

            already_read += copied;
            iocb->ki_pos += copied;
            last_pos = iocb->ki_pos;

    printk("%s: step3 copied(%u) bytes(%u)\n", __func__, copied, bytes);
            if (copied < bytes) {
                error = -EFAULT;
                break;
            }
        }
put_folios:
        for (i = 0; i < folio_batch_count(&fbatch); i++)
            folio_put(fbatch.folios[i]);
        folio_batch_init(&fbatch);
    } while (iov_iter_count(iter) && iocb->ki_pos < isize && !error);

    file_accessed(filp);
    ra->prev_pos = last_pos;
    return already_read ? already_read : error;
}

ssize_t generic_perform_write(struct kiocb *iocb, struct iov_iter *i)
{
    struct file *file = iocb->ki_filp;
    loff_t pos = iocb->ki_pos;
    struct address_space *mapping = file->f_mapping;
    const struct address_space_operations *a_ops = mapping->a_ops;
    size_t chunk = mapping_max_folio_size(mapping);
    long status = 0;
    ssize_t written = 0;

    do {
        struct folio *folio;
        size_t offset;      /* Offset into folio */
        size_t bytes;       /* Bytes to write to folio */
        size_t copied;      /* Bytes copied from user */
        void *fsdata = NULL;

        bytes = iov_iter_count(i);
retry:
        offset = pos & (chunk - 1);
        bytes = min(chunk - offset, bytes);
        balance_dirty_pages_ratelimited(mapping);

        /*
         * Bring in the user page that we will copy from _first_.
         * Otherwise there's a nasty deadlock on copying from the
         * same page as we're writing to, without it being marked
         * up-to-date.
         */
        if (unlikely(fault_in_iov_iter_readable(i, bytes) == bytes)) {
            status = -EFAULT;
            break;
        }

        if (fatal_signal_pending(current)) {
            status = -EINTR;
            break;
        }

        status = a_ops->write_begin(file, mapping, pos, bytes,
                        &folio, &fsdata);
        if (unlikely(status < 0))
            break;

        offset = offset_in_folio(folio, pos);
        if (bytes > folio_size(folio) - offset)
            bytes = folio_size(folio) - offset;

        if (mapping_writably_mapped(mapping))
            flush_dcache_folio(folio);

        copied = copy_folio_from_iter_atomic(folio, offset, bytes, i);
        flush_dcache_folio(folio);

        status = a_ops->write_end(file, mapping, pos, bytes, copied,
                        folio, fsdata);
        if (unlikely(status != copied)) {
            iov_iter_revert(i, copied - max(status, 0L));
            if (unlikely(status < 0))
                break;
        }
        cond_resched();

    printk("%s: step3\n", __func__);
        if (unlikely(status == 0)) {
            /*
             * A short copy made ->write_end() reject the
             * thing entirely.  Might be memory poisoning
             * halfway through, might be a race with munmap,
             * might be severe memory pressure.
             */
            if (chunk > PAGE_SIZE)
                chunk /= 2;
            if (copied) {
                bytes = copied;
                goto retry;
            }
        } else {
            pos += status;
            written += status;
        }
    } while (iov_iter_count(i));

    if (!written)
        return status;
    iocb->ki_pos += written;
    return written;
}

/**
 * file_check_and_advance_wb_err - report wb error (if any) that was previously
 *                 and advance wb_err to current one
 * @file: struct file on which the error is being reported
 *
 * When userland calls fsync (or something like nfsd does the equivalent), we
 * want to report any writeback errors that occurred since the last fsync (or
 * since the file was opened if there haven't been any).
 *
 * Grab the wb_err from the mapping. If it matches what we have in the file,
 * then just quickly return 0. The file is all caught up.
 *
 * If it doesn't match, then take the mapping value, set the "seen" flag in
 * it and try to swap it into place. If it works, or another task beat us
 * to it with the new value, then update the f_wb_err and return the error
 * portion. The error at this point must be reported via proper channels
 * (a'la fsync, or NFS COMMIT operation, etc.).
 *
 * While we handle mapping->wb_err with atomic operations, the f_wb_err
 * value is protected by the f_lock since we must ensure that it reflects
 * the latest value swapped in for this file descriptor.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int file_check_and_advance_wb_err(struct file *file)
{
    int err = 0;
    errseq_t old = READ_ONCE(file->f_wb_err);
    struct address_space *mapping = file->f_mapping;

    printk("%s: step1\n", __func__);
    /* Locklessly handle the common case where nothing has changed */
    if (errseq_check(&mapping->wb_err, old)) {
        /* Something changed, must use slow path */
        spin_lock(&file->f_lock);
        old = file->f_wb_err;
        err = errseq_check_and_advance(&mapping->wb_err,
                        &file->f_wb_err);
        trace_file_check_and_advance_wb_err(file, old);
        spin_unlock(&file->f_lock);
    }

    /*
     * We're mostly using this function as a drop in replacement for
     * filemap_check_errors. Clear AS_EIO/AS_ENOSPC to emulate the effect
     * that the legacy code would have had on these flags.
     */
    clear_bit(AS_EIO, &mapping->flags);
    clear_bit(AS_ENOSPC, &mapping->flags);
    return err;
}

/**
 * file_write_and_wait_range - write out & wait on a file range
 * @file:   file pointing to address_space with pages
 * @lstart: offset in bytes where the range starts
 * @lend:   offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that @lend is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 *
 * After writing out and waiting on the data, we check and advance the
 * f_wb_err cursor to the latest value, and return any errors detected there.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int file_write_and_wait_range(struct file *file, loff_t lstart, loff_t lend)
{
    int err = 0, err2;
    struct address_space *mapping = file->f_mapping;

    if (lend < lstart)
        return 0;

    printk("%s: step1\n", __func__);
    if (mapping_needs_writeback(mapping)) {
        err = __filemap_fdatawrite_range(mapping, lstart, lend,
                         WB_SYNC_ALL);
        /* See comment of filemap_write_and_wait() */
        if (err != -EIO)
            __filemap_fdatawait_range(mapping, lstart, lend);
    }
    printk("%s: step2\n", __func__);
    err2 = file_check_and_advance_wb_err(file);
    printk("%s: step3\n", __func__);
    if (!err)
        err = err2;
    return err;
}

/**
 * filemap_get_folios_tag - Get a batch of folios matching @tag
 * @mapping:    The address_space to search
 * @start:      The starting page index
 * @end:        The final page index (inclusive)
 * @tag:        The tag index
 * @fbatch:     The batch to fill
 *
 * The first folio may start before @start; if it does, it will contain
 * @start.  The final folio may extend beyond @end; if it does, it will
 * contain @end.  The folios have ascending indices.  There may be gaps
 * between the folios if there are indices which have no folio in the
 * page cache.  If folios are added to or removed from the page cache
 * while this is running, they may or may not be found by this call.
 * Only returns folios that are tagged with @tag.
 *
 * Return: The number of folios found.
 * Also update @start to index the next folio for traversal.
 */
unsigned filemap_get_folios_tag(struct address_space *mapping, pgoff_t *start,
            pgoff_t end, xa_mark_t tag, struct folio_batch *fbatch)
{
    XA_STATE(xas, &mapping->i_pages, *start);
    struct folio *folio;

    rcu_read_lock();
    while ((folio = find_get_entry(&xas, end, tag)) != NULL) {
        /*
         * Shadow entries should never be tagged, but this iteration
         * is lockless so there is a window for page reclaim to evict
         * a page we saw tagged. Skip over it.
         */
        if (xa_is_value(folio))
            continue;
        if (!folio_batch_add(fbatch, folio)) {
            unsigned long nr = folio_nr_pages(folio);
            *start = folio->index + nr;
            goto out;
        }
    }
    /*
     * We come here when there is no page beyond @end. We take care to not
     * overflow the index @start as it confuses some of the callers. This
     * breaks the iteration when there is a page at index -1 but that is
     * already broke anyway.
     */
    if (end == (pgoff_t)-1)
        *start = (pgoff_t)-1;
    else
        *start = end + 1;
out:
    rcu_read_unlock();

    return folio_batch_count(fbatch);
}

void folio_wait_bit(struct folio *folio, int bit_nr)
{
    folio_wait_bit_common(folio, bit_nr, TASK_UNINTERRUPTIBLE, SHARED);
}

/**
 * folio_end_writeback - End writeback against a folio.
 * @folio: The folio.
 *
 * The folio must actually be under writeback.
 *
 * Context: May be called from process or interrupt context.
 */
void folio_end_writeback(struct folio *folio)
{
    VM_BUG_ON_FOLIO(!folio_test_writeback(folio), folio);

    printk("%s: step1\n", __func__);
    /*
     * folio_test_clear_reclaim() could be used here but it is an
     * atomic operation and overkill in this particular case. Failing
     * to shuffle a folio marked for immediate reclaim is too mild
     * a gain to justify taking an atomic operation penalty at the
     * end of every folio writeback.
     */
    if (folio_test_reclaim(folio)) {
        folio_clear_reclaim(folio);
        folio_rotate_reclaimable(folio);
    }

    /*
     * Writeback does not hold a folio reference of its own, relying
     * on truncation to wait for the clearing of PG_writeback.
     * But here we must make sure that the folio is not freed and
     * reused before the folio_wake_bit().
     */
    folio_get(folio);
    if (__folio_end_writeback(folio))
        folio_wake_bit(folio, PG_writeback);
    //acct_reclaim_writeback(folio);
    folio_put(folio);
}

void __init pagecache_init(void)
{
    int i;

    for (i = 0; i < PAGE_WAIT_TABLE_SIZE; i++)
        init_waitqueue_head(&folio_wait_table[i]);

    page_writeback_init();
}
