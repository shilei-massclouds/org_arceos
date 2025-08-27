#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>

#ifdef CONFIG_MMIOWB
#ifndef arch_mmiowb_state
DEFINE_PER_CPU(struct mmiowb_state, __mmiowb_state);
EXPORT_PER_CPU_SYMBOL(__mmiowb_state);
#endif
#endif

noinline int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock)
{
    return __raw_spin_trylock(lock);
}

noinline unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock)
{
    return __raw_spin_lock_irqsave(lock);
}

noinline void __lockfunc _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
    __raw_spin_unlock_irqrestore(lock, flags);
}

noinline void __lockfunc _raw_spin_lock(raw_spinlock_t *lock)
{
    __raw_spin_lock(lock);
}

noinline void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock)
{
    __raw_spin_unlock(lock);
}

noinline void __lockfunc _raw_spin_lock_irq(raw_spinlock_t *lock)
{
    __raw_spin_lock_irq(lock);
}

noinline void __lockfunc _raw_spin_unlock_irq(raw_spinlock_t *lock)
{
    __raw_spin_unlock_irq(lock);
}

noinline void __lockfunc _raw_spin_lock_bh(raw_spinlock_t *lock)
{
    __raw_spin_lock_bh(lock);
}

noinline void __lockfunc _raw_spin_unlock_bh(raw_spinlock_t *lock)
{
    __raw_spin_unlock_bh(lock);
}

void __lockfunc _raw_write_lock(rwlock_t *lock)
{
    pr_notice("%s: ===> WARN: impl it.\n", __func__);
}

void __lockfunc _raw_write_unlock(rwlock_t *lock)
{
    pr_notice("%s: ===> WARN: impl it.\n", __func__);
}

noinline void __lockfunc _raw_read_lock(rwlock_t *lock)
{
    pr_notice("%s: ===> WARN: impl it.\n", __func__);
}

noinline void __lockfunc _raw_read_unlock(rwlock_t *lock)
{
    pr_notice("%s: ===> WARN: impl it.\n", __func__);
}
