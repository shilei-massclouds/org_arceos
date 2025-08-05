#include <linux/percpu_counter.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/debugobjects.h>

#include "../adaptor.h"

#ifdef CONFIG_HOTPLUG_CPU
static LIST_HEAD(percpu_counters);
static DEFINE_SPINLOCK(percpu_counters_lock);
#endif

/*
 * Add up all the per-cpu counts, return the result.  This is a more accurate
 * but much slower version of percpu_counter_read_positive().
 *
 * We use the cpu mask of (cpu_online_mask | cpu_dying_mask) to capture sums
 * from CPUs that are in the process of being taken offline. Dying cpus have
 * been removed from the online mask, but may not have had the hotplug dead
 * notifier called to fold the percpu count back into the global counter sum.
 * By including dying CPUs in the iteration mask, we avoid this race condition
 * so __percpu_counter_sum() just does the right thing when CPUs are being taken
 * offline.
 */
s64 __percpu_counter_sum(struct percpu_counter *fbc)
{
    s64 ret;
    int cpu;
    unsigned long flags;

    raw_spin_lock_irqsave(&fbc->lock, flags);
    ret = fbc->count;
    for_each_cpu_or(cpu, cpu_online_mask, cpu_dying_mask) {
        s32 *pcount = per_cpu_ptr(fbc->counters, cpu);
        ret += *pcount;
    }
    raw_spin_unlock_irqrestore(&fbc->lock, flags);
    return ret;
}

int __percpu_counter_init_many(struct percpu_counter *fbc, s64 amount,
                   gfp_t gfp, u32 nr_counters,
                   struct lock_class_key *key)
{
    unsigned long flags __maybe_unused;
    size_t counter_size;
    s32 __percpu *counters;
    u32 i;

    counter_size = ALIGN(sizeof(*counters), __alignof__(*counters));
    counters = __alloc_percpu_gfp(nr_counters * counter_size,
                      __alignof__(*counters), gfp);
    if (!counters) {
        fbc[0].counters = NULL;
        return -ENOMEM;
    }

    for (i = 0; i < nr_counters; i++) {
        raw_spin_lock_init(&fbc[i].lock);
        lockdep_set_class(&fbc[i].lock, key);
#ifdef CONFIG_HOTPLUG_CPU
        INIT_LIST_HEAD(&fbc[i].list);
#endif
        fbc[i].count = amount;
        fbc[i].counters = (void __percpu *)counters + i * counter_size;

        //debug_percpu_counter_activate(&fbc[i]);
    }

#ifdef CONFIG_HOTPLUG_CPU
    spin_lock_irqsave(&percpu_counters_lock, flags);
    for (i = 0; i < nr_counters; i++)
        list_add(&fbc[i].list, &percpu_counters);
    spin_unlock_irqrestore(&percpu_counters_lock, flags);
#endif
    return 0;
}
