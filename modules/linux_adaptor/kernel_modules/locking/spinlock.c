#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/sched/debug.h>

#ifdef CONFIG_MMIOWB
#ifndef arch_mmiowb_state
DEFINE_PER_CPU(struct mmiowb_state, __mmiowb_state);
EXPORT_PER_CPU_SYMBOL(__mmiowb_state);
#endif
#endif

noinline unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock)
{
    unsigned long flags;

    local_irq_save(flags);

    /* For simplicity, ignore kernel-preemption. */
    // preempt_disable();

    arch_spin_lock(&lock->raw_lock);

    return flags;
}

noinline void __lockfunc _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
    arch_spin_unlock(&lock->raw_lock);

    local_irq_restore(flags);

    /* For simplicity, ignore kernel-preemption. */
    // preempt_enable();
}

noinline void __lockfunc _raw_spin_lock(raw_spinlock_t *lock)
{
    /* For simplicity, ignore kernel-preemption. */
    // preempt_disable();

    arch_spin_lock(&lock->raw_lock);
}

noinline void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock)
{
    arch_spin_unlock(&lock->raw_lock);

    /* For simplicity, ignore kernel-preemption. */
    // preempt_enable();
}

noinline void __lockfunc _raw_spin_lock_irq(raw_spinlock_t *lock)
{
    local_irq_disable();

    /* For simplicity, ignore kernel-preemption. */
    // preempt_disable();

    arch_spin_lock(&lock->raw_lock);
}

noinline void __lockfunc _raw_spin_unlock_irq(raw_spinlock_t *lock)
{
    arch_spin_unlock(&lock->raw_lock);

    local_irq_enable();

    /* For simplicity, ignore kernel-preemption. */
    // preempt_enable();
}

noinline void __lockfunc _raw_spin_lock_bh(raw_spinlock_t *lock)
{
    pr_err("%s: ===> WARN: impl it.\n", __func__);
}

noinline void __lockfunc _raw_spin_unlock_bh(raw_spinlock_t *lock)
{
    pr_err("%s: ===> WARN: impl it.\n", __func__);
}

void __lockfunc _raw_write_lock(rwlock_t *lock)
{
    pr_err("%s: ===> WARN: impl it.\n", __func__);
}

void __lockfunc _raw_write_unlock(rwlock_t *lock)
{
    pr_err("%s: ===> WARN: impl it.\n", __func__);
}

noinline void __lockfunc _raw_read_lock(rwlock_t *lock)
{
    pr_err("%s: ===> WARN: impl it.\n", __func__);
}

noinline void __lockfunc _raw_read_unlock(rwlock_t *lock)
{
    pr_err("%s: ===> WARN: impl it.\n", __func__);
}
