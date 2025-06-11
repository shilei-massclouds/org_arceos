#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include "booter.h"

void __raw_spin_lock_init(raw_spinlock_t *lock, const char *name,
              struct lock_class_key *key, short inner)
{
    log_error("%s: WARN: impl it. (%lx) (%s)\n",
           __func__, (unsigned long)lock, name);
}

void __lockfunc _raw_spin_lock(raw_spinlock_t *lock)
{
    log_error("%s: ===> WARN: impl it. (%lx)\n", __func__, (unsigned long)lock);
}

void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock)
{
    log_error("%s: ===> WARN: impl it. (%lx)\n", __func__, (unsigned long)lock);
}

unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock)
{
    log_error("%s: ===> WARN: impl it. (%lx)\n", __func__, (unsigned long)lock);
}

void __lockfunc _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
    log_error("%s: ===> WARN: impl it. (%lx)\n", __func__, (unsigned long)lock);
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
