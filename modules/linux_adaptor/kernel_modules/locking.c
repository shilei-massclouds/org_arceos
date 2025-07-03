#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/sched/debug.h>

#include "booter.h"

void __raw_spin_lock_init(raw_spinlock_t *lock, const char *name,
              struct lock_class_key *key, short inner)
{
    lock->raw_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
    lock->magic = SPINLOCK_MAGIC;
    lock->owner = SPINLOCK_OWNER_INIT;
    lock->owner_cpu = -1;
}

void __lockfunc _raw_spin_lock(raw_spinlock_t *lock)
{
    /* For simplicity, ignore kernel-preemption. */
    // preempt_disable();

    arch_spin_lock(&lock->raw_lock);
}

void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock)
{
    arch_spin_unlock(&lock->raw_lock);

    /* For simplicity, ignore kernel-preemption. */
    // preempt_enable();
}

unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock)
{
    unsigned long flags;

    local_irq_save(flags);

    /* For simplicity, ignore kernel-preemption. */
    // preempt_disable();

    arch_spin_lock(&lock->raw_lock);

    return flags;
}

void __lockfunc _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
    arch_spin_unlock(&lock->raw_lock);

    local_irq_restore(flags);

    /* For simplicity, ignore kernel-preemption. */
    // preempt_enable();
}

void __lockfunc _raw_spin_lock_irq(raw_spinlock_t *lock)
{
    local_irq_disable();

    /* For simplicity, ignore kernel-preemption. */
    // preempt_disable();

    arch_spin_lock(&lock->raw_lock);
}

void __lockfunc _raw_spin_unlock_irq(raw_spinlock_t *lock)
{
    arch_spin_unlock(&lock->raw_lock);

    local_irq_enable();

    /* For simplicity, ignore kernel-preemption. */
    // preempt_enable();
}

int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock)
{
    return arch_spin_trylock(&(lock)->raw_lock);
}

void
__mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
{
    log_debug("%s: ===> WARN: impl it. (%lx) (%s)\n", __func__, (unsigned long)lock, name);
}

void __rwlock_init(rwlock_t *lock, const char *name,
           struct lock_class_key *key)
{
    log_debug("%s: ===> WARN: impl it. (%lx) (%s)\n", __func__, (unsigned long)lock, name);
}

void __lockfunc _raw_read_lock(rwlock_t *lock)
{
    log_debug("%s: ===> WARN: impl it.\n", __func__);
}

void __lockfunc _raw_read_unlock(rwlock_t *lock)
{
    log_debug("%s: ===> WARN: impl it.\n", __func__);
}

/*
 * lock for reading
 */
void __sched down_read(struct rw_semaphore *sem)
{
    log_debug("%s: ===> WARN: impl it.\n", __func__);
}

void __lockfunc _raw_write_lock(rwlock_t *lock)
{
    log_debug("%s: ===> WARN: impl it.\n", __func__);
}

void __lockfunc _raw_write_unlock(rwlock_t *lock)
{
    log_debug("%s: ===> WARN: impl it.\n", __func__);
}

/*
 * release a read lock
 */
void up_read(struct rw_semaphore *sem)
{
    log_debug("%s: ===> WARN: impl it.\n", __func__);
}

void __sched mutex_lock(struct mutex *lock)
{
    log_error("%s: ===> WARN: impl it.\n", __func__);
}

void __sched mutex_unlock(struct mutex *lock)
{
    log_error("%s: ===> WARN: impl it.\n", __func__);
}

/*
 * Initialize an rwsem:
 */
void __init_rwsem(struct rw_semaphore *sem, const char *name,
          struct lock_class_key *key)
{
    log_error("%s: ===> WARN: impl it.\n", __func__);
}

int __percpu_init_rwsem(struct percpu_rw_semaphore *sem,
            const char *name, struct lock_class_key *key)
{
    log_error("%s: ===> WARN: impl it.\n", __func__);
}

/*
 * lock for writing
 */
void __sched down_write(struct rw_semaphore *sem)
{
    log_error("%s: ===> WARN: impl it.\n", __func__);
}

/*
 * release a write lock
 */
void up_write(struct rw_semaphore *sem)
{
    log_error("%s: ===> WARN: impl it.\n", __func__);
}
