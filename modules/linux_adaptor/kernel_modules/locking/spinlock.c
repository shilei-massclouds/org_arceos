#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/sched/debug.h>

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
