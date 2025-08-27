#include <linux/spinlock.h>
#include <linux/nmi.h>
#include <linux/interrupt.h>
#include <linux/debug_locks.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/pid.h>

static void spin_dump(raw_spinlock_t *lock, const char *msg)
{
    struct task_struct *owner = READ_ONCE(lock->owner);

    if (owner == SPINLOCK_OWNER_INIT)
        owner = NULL;
    printk(KERN_EMERG "BUG: spinlock %s on CPU#%d, %s/%d\n",
        msg, raw_smp_processor_id(),
        current->comm, task_pid_nr(current));
    printk(KERN_EMERG " lock: %lx, .magic: %08x, .owner: %s/%d, "
            ".owner_cpu: %d\n",
        lock, READ_ONCE(lock->magic),
        owner ? owner->comm : "<none>",
        owner ? task_pid_nr(owner) : -1,
        READ_ONCE(lock->owner_cpu));
    dump_stack();
}

static void spin_bug(raw_spinlock_t *lock, const char *msg)
{
    if (!debug_locks_off())
        return;

    spin_dump(lock, msg);
}

#define SPIN_BUG_ON(cond, lock, msg) if (unlikely(cond)) spin_bug(lock, msg)

static inline void
debug_spin_lock_before(raw_spinlock_t *lock)
{
    SPIN_BUG_ON(READ_ONCE(lock->magic) != SPINLOCK_MAGIC, lock, "bad magic");
    SPIN_BUG_ON(READ_ONCE(lock->owner) == current, lock, "recursion");
    SPIN_BUG_ON(READ_ONCE(lock->owner_cpu) == raw_smp_processor_id(),
                            lock, "cpu recursion");
}

static inline void debug_spin_lock_after(raw_spinlock_t *lock)
{
    WRITE_ONCE(lock->owner_cpu, raw_smp_processor_id());
    WRITE_ONCE(lock->owner, current);
}

static inline void debug_spin_unlock(raw_spinlock_t *lock)
{
    SPIN_BUG_ON(lock->magic != SPINLOCK_MAGIC, lock, "bad magic");
    SPIN_BUG_ON(!raw_spin_is_locked(lock), lock, "already unlocked");
    SPIN_BUG_ON(lock->owner != current, lock, "wrong owner");
    SPIN_BUG_ON(lock->owner_cpu != raw_smp_processor_id(),
                            lock, "wrong CPU");
    WRITE_ONCE(lock->owner, SPINLOCK_OWNER_INIT);
    WRITE_ONCE(lock->owner_cpu, -1);
}

void __raw_spin_lock_init(raw_spinlock_t *lock, const char *name,
              struct lock_class_key *key, short inner)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
    /*
     * Make sure we are not reinitializing a held lock:
     */
    debug_check_no_locks_freed((void *)lock, sizeof(*lock));
    lockdep_init_map_wait(&lock->dep_map, name, key, 0, inner);
#endif
    lock->raw_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
    lock->magic = SPINLOCK_MAGIC;
    lock->owner = SPINLOCK_OWNER_INIT;
    lock->owner_cpu = -1;
}

void __rwlock_init(rwlock_t *lock, const char *name,
           struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
    /*
     * Make sure we are not reinitializing a held lock:
     */
    debug_check_no_locks_freed((void *)lock, sizeof(*lock));
    lockdep_init_map_wait(&lock->dep_map, name, key, 0, LD_WAIT_CONFIG);
#endif
    lock->raw_lock = (arch_rwlock_t) __ARCH_RW_LOCK_UNLOCKED;
    lock->magic = RWLOCK_MAGIC;
    lock->owner = SPINLOCK_OWNER_INIT;
    lock->owner_cpu = -1;
}

int do_raw_spin_trylock(raw_spinlock_t *lock)
{
    int ret = arch_spin_trylock(&lock->raw_lock);

    if (ret) {
        mmiowb_spin_lock();
        debug_spin_lock_after(lock);
    }
#ifndef CONFIG_SMP
    /*
     * Must not happen on UP:
     */
    SPIN_BUG_ON(!ret, lock, "trylock failure on UP");
#endif
    return ret;
}

/*
 * We are now relying on the NMI watchdog to detect lockup instead of doing
 * the detection here with an unfair lock which can cause problem of its own.
 */
void do_raw_spin_lock(raw_spinlock_t *lock)
{
    debug_spin_lock_before(lock);
    arch_spin_lock(&lock->raw_lock);
    mmiowb_spin_lock();
    debug_spin_lock_after(lock);
}

void do_raw_spin_unlock(raw_spinlock_t *lock)
{
    mmiowb_spin_unlock();
    debug_spin_unlock(lock);
    arch_spin_unlock(&lock->raw_lock);
}
