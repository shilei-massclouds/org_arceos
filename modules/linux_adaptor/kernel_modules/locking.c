#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
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
    log_debug("%s: ===> WARN: impl it. (%lx)\n", __func__, (unsigned long)lock);
}

void __lockfunc _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
    log_debug("%s: ===> WARN: impl it. (%lx)\n", __func__, (unsigned long)lock);
}

void __lockfunc _raw_spin_lock_irq(raw_spinlock_t *lock)
{
    log_error("%s: ===> WARN: impl it. (%lx)\n",
           __func__, (unsigned long)lock);
}

void __lockfunc _raw_spin_unlock_irq(raw_spinlock_t *lock)
{
    log_error("%s: ===> WARN: impl it. (%lx)\n",
           __func__, (unsigned long)lock);
}

void
__mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
{
    log_error("%s: ===> WARN: impl it. (%lx) (%s)\n", __func__, (unsigned long)lock, name);
}
