#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#include <linux/sched/debug.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/signal.h>
#include <linux/sched/clock.h>
#include <linux/export.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>
#include <trace/events/lock.h>

#include "lock_events.h"
#include "../adaptor.h"

/*
 * The least significant 2 bits of the owner value has the following
 * meanings when set.
 *  - Bit 0: RWSEM_READER_OWNED - rwsem may be owned by readers (just a hint)
 *  - Bit 1: RWSEM_NONSPINNABLE - Cannot spin on a reader-owned lock
 *
 * When the rwsem is reader-owned and a spinning writer has timed out,
 * the nonspinnable bit will be set to disable optimistic spinning.

 * When a writer acquires a rwsem, it puts its task_struct pointer
 * into the owner field. It is cleared after an unlock.
 *
 * When a reader acquires a rwsem, it will also puts its task_struct
 * pointer into the owner field with the RWSEM_READER_OWNED bit set.
 * On unlock, the owner field will largely be left untouched. So
 * for a free or reader-owned rwsem, the owner value may contain
 * information about the last reader that acquires the rwsem.
 *
 * That information may be helpful in debugging cases where the system
 * seems to hang on a reader owned rwsem especially if only one reader
 * is involved. Ideally we would like to track all the readers that own
 * a rwsem, but the overhead is simply too big.
 *
 * A fast path reader optimistic lock stealing is supported when the rwsem
 * is previously owned by a writer and the following conditions are met:
 *  - rwsem is not currently writer owned
 *  - the handoff isn't set.
 */
#define RWSEM_READER_OWNED  (1UL << 0)
#define RWSEM_NONSPINNABLE  (1UL << 1)
#define RWSEM_OWNER_FLAGS_MASK  (RWSEM_READER_OWNED | RWSEM_NONSPINNABLE)

# define DEBUG_RWSEMS_WARN_ON(c, sem)   do {            \
    if (!debug_locks_silent &&              \
        WARN_ONCE(c, "DEBUG_RWSEMS_WARN_ON(%s): count = 0x%lx, magic = 0x%lx, owner = 0x%lx, curr 0x%lx, list %sempty\n",\
        #c, atomic_long_read(&(sem)->count),        \
        (unsigned long) sem->magic,         \
        atomic_long_read(&(sem)->owner), (long)current, \
        list_empty(&(sem)->wait_list) ? "" : "not "))   \
            debug_locks_off();          \
    } while (0)

/*
 * On 64-bit architectures, the bit definitions of the count are:
 *
 * Bit  0    - writer locked bit
 * Bit  1    - waiters present bit
 * Bit  2    - lock handoff bit
 * Bits 3-7  - reserved
 * Bits 8-62 - 55-bit reader count
 * Bit  63   - read fail bit
 *
 * On 32-bit architectures, the bit definitions of the count are:
 *
 * Bit  0    - writer locked bit
 * Bit  1    - waiters present bit
 * Bit  2    - lock handoff bit
 * Bits 3-7  - reserved
 * Bits 8-30 - 23-bit reader count
 * Bit  31   - read fail bit
 *
 * It is not likely that the most significant bit (read fail bit) will ever
 * be set. This guard bit is still checked anyway in the down_read() fastpath
 * just in case we need to use up more of the reader bits for other purpose
 * in the future.
 *
 * atomic_long_fetch_add() is used to obtain reader lock, whereas
 * atomic_long_cmpxchg() will be used to obtain writer lock.
 *
 * There are three places where the lock handoff bit may be set or cleared.
 * 1) rwsem_mark_wake() for readers     -- set, clear
 * 2) rwsem_try_write_lock() for writers    -- set, clear
 * 3) rwsem_del_waiter()            -- clear
 *
 * For all the above cases, wait_lock will be held. A writer must also
 * be the first one in the wait_list to be eligible for setting the handoff
 * bit. So concurrent setting/clearing of handoff bit is not possible.
 */
#define RWSEM_WRITER_LOCKED (1UL << 0)
#define RWSEM_FLAG_WAITERS  (1UL << 1)
#define RWSEM_FLAG_HANDOFF  (1UL << 2)
#define RWSEM_FLAG_READFAIL (1UL << (BITS_PER_LONG - 1))

#define RWSEM_READER_SHIFT  8
#define RWSEM_READER_BIAS   (1UL << RWSEM_READER_SHIFT)
#define RWSEM_READER_MASK   (~(RWSEM_READER_BIAS - 1))
#define RWSEM_WRITER_MASK   RWSEM_WRITER_LOCKED
#define RWSEM_LOCK_MASK     (RWSEM_WRITER_MASK|RWSEM_READER_MASK)
#define RWSEM_READ_FAILED_MASK  (RWSEM_WRITER_MASK|RWSEM_FLAG_WAITERS|\
                 RWSEM_FLAG_HANDOFF|RWSEM_FLAG_READFAIL)

enum rwsem_wake_type {
    RWSEM_WAKE_ANY,     /* Wake whatever's at head of wait list */
    RWSEM_WAKE_READERS, /* Wake readers only */
    RWSEM_WAKE_READ_OWNED   /* Waker thread holds the read lock */
};

/*
 * Test the flags in the owner field.
 */
static inline bool rwsem_test_oflags(struct rw_semaphore *sem, long flags)
{
    return atomic_long_read(&sem->owner) & flags;
}

/*
 * Return just the real task structure pointer of the owner
 */
static inline struct task_struct *rwsem_owner(struct rw_semaphore *sem)
{
    return (struct task_struct *)
        (atomic_long_read(&sem->owner) & ~RWSEM_OWNER_FLAGS_MASK);
}

/*
 * Return true if the rwsem is owned by a reader.
 */
static inline bool is_rwsem_reader_owned(struct rw_semaphore *sem)
{
    /*
     * Check the count to see if it is write-locked.
     */
    long count = atomic_long_read(&sem->count);

    if (count & RWSEM_WRITER_MASK)
        return false;
    return rwsem_test_oflags(sem, RWSEM_READER_OWNED);
}

/*
 * All writes to owner are protected by WRITE_ONCE() to make sure that
 * store tearing can't happen as optimistic spinners may read and use
 * the owner value concurrently without lock. Read from owner, however,
 * may not need READ_ONCE() as long as the pointer value is only used
 * for comparison and isn't being dereferenced.
 *
 * Both rwsem_{set,clear}_owner() functions should be in the same
 * preempt disable section as the atomic op that changes sem->count.
 */
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
    lockdep_assert_preemption_disabled();
    atomic_long_set(&sem->owner, (long)current);
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
    lockdep_assert_preemption_disabled();
    atomic_long_set(&sem->owner, 0);
}

/*
 * Guide to the rw_semaphore's count field.
 *
 * When the RWSEM_WRITER_LOCKED bit in count is set, the lock is owned
 * by a writer.
 *
 * The lock is owned by readers when
 * (1) the RWSEM_WRITER_LOCKED isn't set in count,
 * (2) some of the reader bits are set in count, and
 * (3) the owner field has RWSEM_READ_OWNED bit set.
 *
 * Having some reader bits set is not enough to guarantee a readers owned
 * lock as the readers may be in the process of backing out from the count
 * and a writer has just released the lock. So another writer may steal
 * the lock immediately after that.
 */

/*
 * Initialize an rwsem:
 */
void __init_rwsem(struct rw_semaphore *sem, const char *name,
          struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
    /*
     * Make sure we are not reinitializing a held semaphore:
     */
    debug_check_no_locks_freed((void *)sem, sizeof(*sem));
    lockdep_init_map_wait(&sem->dep_map, name, key, 0, LD_WAIT_SLEEP);
#endif
#ifdef CONFIG_DEBUG_RWSEMS
    sem->magic = sem;
#endif
    atomic_long_set(&sem->count, RWSEM_UNLOCKED_VALUE);
    raw_spin_lock_init(&sem->wait_lock);
    INIT_LIST_HEAD(&sem->wait_list);
    atomic_long_set(&sem->owner, 0L);
#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
    osq_lock_init(&sem->osq);
#endif
}

static inline bool rwsem_write_trylock(struct rw_semaphore *sem)
{
    long tmp = RWSEM_UNLOCKED_VALUE;

    if (atomic_long_try_cmpxchg_acquire(&sem->count, &tmp, RWSEM_WRITER_LOCKED)) {
        rwsem_set_owner(sem);
        return true;
    }

    return false;
}

/*
 * Wait until we successfully acquire the write lock
 */
static struct rw_semaphore __sched *
rwsem_down_write_slowpath(struct rw_semaphore *sem, int state)
{
    PANIC("");
}

/*
 * The task_struct pointer of the last owning reader will be left in
 * the owner field.
 *
 * Note that the owner value just indicates the task has owned the rwsem
 * previously, it may not be the real owner or one of the real owners
 * anymore when that field is examined, so take it with a grain of salt.
 *
 * The reader non-spinnable bit is preserved.
 */
static inline void __rwsem_set_reader_owned(struct rw_semaphore *sem,
                        struct task_struct *owner)
{
    unsigned long val = (unsigned long)owner | RWSEM_READER_OWNED |
        (atomic_long_read(&sem->owner) & RWSEM_NONSPINNABLE);

    atomic_long_set(&sem->owner, val);
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
    __rwsem_set_reader_owned(sem, current);
}

static inline int __down_read_trylock(struct rw_semaphore *sem)
{
    int ret = 0;
    long tmp;

    DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);

    preempt_disable();
    tmp = atomic_long_read(&sem->count);
    while (!(tmp & RWSEM_READ_FAILED_MASK)) {
        if (atomic_long_try_cmpxchg_acquire(&sem->count, &tmp,
                            tmp + RWSEM_READER_BIAS)) {
            rwsem_set_reader_owned(sem);
            ret = 1;
            break;
        }
    }
    preempt_enable();
    return ret;
}

/*
 * lock for writing
 */
static __always_inline int __down_write_common(struct rw_semaphore *sem, int state)
{
    int ret = 0;

    preempt_disable();
    if (unlikely(!rwsem_write_trylock(sem))) {
        if (IS_ERR(rwsem_down_write_slowpath(sem, state)))
            ret = -EINTR;
    }
    preempt_enable();
    return ret;
}

static __always_inline void __down_write(struct rw_semaphore *sem)
{
    __down_write_common(sem, TASK_UNINTERRUPTIBLE);
}

/*
 * Set the RWSEM_NONSPINNABLE bits if the RWSEM_READER_OWNED flag
 * remains set. Otherwise, the operation will be aborted.
 */
static inline void rwsem_set_nonspinnable(struct rw_semaphore *sem)
{
    unsigned long owner = atomic_long_read(&sem->owner);

    do {
        if (!(owner & RWSEM_READER_OWNED))
            break;
        if (owner & RWSEM_NONSPINNABLE)
            break;
    } while (!atomic_long_try_cmpxchg(&sem->owner, &owner,
                      owner | RWSEM_NONSPINNABLE));
}

static inline bool rwsem_read_trylock(struct rw_semaphore *sem, long *cntp)
{
    *cntp = atomic_long_add_return_acquire(RWSEM_READER_BIAS, &sem->count);

    if (WARN_ON_ONCE(*cntp < 0))
        rwsem_set_nonspinnable(sem);

    if (!(*cntp & RWSEM_READ_FAILED_MASK)) {
        rwsem_set_reader_owned(sem);
        return true;
    }

    return false;
}

/*
 * Wait for the read lock to be granted
 */
static struct rw_semaphore __sched *
rwsem_down_read_slowpath(struct rw_semaphore *sem, long count, unsigned int state)
{
    PANIC("");
}

/*
 * lock for reading
 */
static __always_inline int __down_read_common(struct rw_semaphore *sem, int state)
{
    int ret = 0;
    long count;

    preempt_disable();
    if (!rwsem_read_trylock(sem, &count)) {
        if (IS_ERR(rwsem_down_read_slowpath(sem, count, state))) {
            ret = -EINTR;
            goto out;
        }
        DEBUG_RWSEMS_WARN_ON(!is_rwsem_reader_owned(sem), sem);
    }
out:
    preempt_enable();
    return ret;
}

static __always_inline void __down_read(struct rw_semaphore *sem)
{
    __down_read_common(sem, TASK_UNINTERRUPTIBLE);
}

static __always_inline int __down_read_killable(struct rw_semaphore *sem)
{
    return __down_read_common(sem, TASK_KILLABLE);
}

/*
 * lock for writing
 */
void __sched down_write(struct rw_semaphore *sem)
{
    might_sleep();
    rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);
    LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
}

int __sched down_read_killable(struct rw_semaphore *sem)
{
    might_sleep();
    rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

    if (LOCK_CONTENDED_RETURN(sem, __down_read_trylock, __down_read_killable)) {
        rwsem_release(&sem->dep_map, _RET_IP_);
        return -EINTR;
    }

    return 0;
}

/*
 * handle the lock release when processes blocked on it that can now run
 * - if we come here from up_xxxx(), then the RWSEM_FLAG_WAITERS bit must
 *   have been set.
 * - there must be someone on the queue
 * - the wait_lock must be held by the caller
 * - tasks are marked for wakeup, the caller must later invoke wake_up_q()
 *   to actually wakeup the blocked task(s) and drop the reference count,
 *   preferably when the wait_lock is released
 * - woken process blocks are discarded from the list after having task zeroed
 * - writers are only marked woken if downgrading is false
 *
 * Implies rwsem_del_waiter() for all woken readers.
 */
static void rwsem_mark_wake(struct rw_semaphore *sem,
                enum rwsem_wake_type wake_type,
                struct wake_q_head *wake_q)
{
    PANIC("");
}

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int down_read_trylock(struct rw_semaphore *sem)
{
    int ret = __down_read_trylock(sem);

    if (ret == 1)
        rwsem_acquire_read(&sem->dep_map, 0, 1, _RET_IP_);
    return ret;
}

/*
 * handle waking up a waiter on the semaphore
 * - up_read/up_write has decremented the active part of count if we come here
 */
static struct rw_semaphore *rwsem_wake(struct rw_semaphore *sem)
{
    unsigned long flags;
    DEFINE_WAKE_Q(wake_q);

    raw_spin_lock_irqsave(&sem->wait_lock, flags);

    if (!list_empty(&sem->wait_list))
        rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);

    raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
    wake_up_q(&wake_q);

    return sem;
}

/*
 * With CONFIG_DEBUG_RWSEMS configured, it will make sure that if there
 * is a task pointer in owner of a reader-owned rwsem, it will be the
 * real owner or one of the real owners. The only exception is when the
 * unlock is done by up_read_non_owner().
 */
static inline void rwsem_clear_reader_owned(struct rw_semaphore *sem)
{
    unsigned long val = atomic_long_read(&sem->owner);

    while ((val & ~RWSEM_OWNER_FLAGS_MASK) == (unsigned long)current) {
        if (atomic_long_try_cmpxchg(&sem->owner, &val,
                        val & RWSEM_OWNER_FLAGS_MASK))
            return;
    }
}

/*
 * Clear the owner's RWSEM_NONSPINNABLE bit if it is set. This should
 * only be called when the reader count reaches 0.
 */
static inline void clear_nonspinnable(struct rw_semaphore *sem)
{
    if (unlikely(rwsem_test_oflags(sem, RWSEM_NONSPINNABLE)))
        atomic_long_andnot(RWSEM_NONSPINNABLE, &sem->owner);
}

/*
 * unlock after reading
 */
static inline void __up_read(struct rw_semaphore *sem)
{
    long tmp;

    DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);
    DEBUG_RWSEMS_WARN_ON(!is_rwsem_reader_owned(sem), sem);

    preempt_disable();
    rwsem_clear_reader_owned(sem);
    tmp = atomic_long_add_return_release(-RWSEM_READER_BIAS, &sem->count);
    DEBUG_RWSEMS_WARN_ON(tmp < 0, sem);
    if (unlikely((tmp & (RWSEM_LOCK_MASK|RWSEM_FLAG_WAITERS)) ==
              RWSEM_FLAG_WAITERS)) {
        clear_nonspinnable(sem);
        rwsem_wake(sem);
    }
    preempt_enable();
}

/*
 * unlock after writing
 */
static inline void __up_write(struct rw_semaphore *sem)
{
    long tmp;

    DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);
    /*
     * sem->owner may differ from current if the ownership is transferred
     * to an anonymous writer by setting the RWSEM_NONSPINNABLE bits.
     */
    DEBUG_RWSEMS_WARN_ON((rwsem_owner(sem) != current) &&
                !rwsem_test_oflags(sem, RWSEM_NONSPINNABLE), sem);

    preempt_disable();
    rwsem_clear_owner(sem);
    tmp = atomic_long_fetch_add_release(-RWSEM_WRITER_LOCKED, &sem->count);
    if (unlikely(tmp & RWSEM_FLAG_WAITERS))
        rwsem_wake(sem);
    preempt_enable();
}

/*
 * release a read lock
 */
void up_read(struct rw_semaphore *sem)
{
    rwsem_release(&sem->dep_map, _RET_IP_);
    __up_read(sem);
}

/*
 * release a write lock
 */
void up_write(struct rw_semaphore *sem)
{
    rwsem_release(&sem->dep_map, _RET_IP_);
    __up_write(sem);
}

/*
 * lock for reading
 */
void __sched down_read(struct rw_semaphore *sem)
{
    might_sleep();
    rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

    LOCK_CONTENDED(sem, __down_read_trylock, __down_read);
}
