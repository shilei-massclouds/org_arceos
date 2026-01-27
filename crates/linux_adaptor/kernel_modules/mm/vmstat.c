#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/vmstat.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/sched.h>
#include <linux/math64.h>
#include <linux/writeback.h>
#include <linux/compaction.h>
#include <linux/mm_inline.h>
#include <linux/page_owner.h>
#include <linux/sched/isolation.h>

#include "internal.h"
#include "adaptor.h"

DEFINE_PER_CPU(struct vm_event_state, vm_event_states) = {{0}};

/*
 * Manage combined zone based / global counters
 *
 * vm_stat contains the global counters
 */
atomic_long_t vm_zone_stat[NR_VM_ZONE_STAT_ITEMS] __cacheline_aligned_in_smp;
atomic_long_t vm_node_stat[NR_VM_NODE_STAT_ITEMS] __cacheline_aligned_in_smp;
atomic_long_t vm_numa_event[NR_VM_NUMA_EVENT_ITEMS] __cacheline_aligned_in_smp;

/*
 * For use when we know that interrupts are disabled,
 * or when we know that preemption is disabled and that
 * particular counter cannot be updated from interrupt context.
 */
void __mod_zone_page_state(struct zone *zone, enum zone_stat_item item,
               long delta)
{
#if 0
    struct per_cpu_zonestat __percpu *pcp = zone->per_cpu_zonestats;
    s8 __percpu *p = pcp->vm_stat_diff + item;
    long x;
    long t;

    /*
     * Accurate vmstat updates require a RMW. On !PREEMPT_RT kernels,
     * atomicity is provided by IRQs being disabled -- either explicitly
     * or via local_lock_irq. On PREEMPT_RT, local_lock_irq only disables
     * CPU migrations and preemption potentially corrupts a counter so
     * disable preemption.
     */
    preempt_disable_nested();

    x = delta + __this_cpu_read(*p);

    t = __this_cpu_read(pcp->stat_threshold);

    if (unlikely(abs(x) > t)) {
        zone_page_state_add(x, zone, item);
        x = 0;
    }
    __this_cpu_write(*p, x);

    preempt_enable_nested();
#endif
    PANIC("");
}

/*
 * Use interrupt disable to serialize counter updates
 */
void mod_zone_page_state(struct zone *zone, enum zone_stat_item item,
             long delta)
{
    unsigned long flags;

    local_irq_save(flags);
    __mod_zone_page_state(zone, item, delta);
    local_irq_restore(flags);
}

void __mod_node_page_state(struct pglist_data *pgdat, enum node_stat_item item,
                long delta)
{
#if 0
    struct per_cpu_nodestat __percpu *pcp = pgdat->per_cpu_nodestats;
    s8 __percpu *p = pcp->vm_node_stat_diff + item;
    long x;
    long t;

    if (vmstat_item_in_bytes(item)) {
        /*
         * Only cgroups use subpage accounting right now; at
         * the global level, these items still change in
         * multiples of whole pages. Store them as pages
         * internally to keep the per-cpu counters compact.
         */
        VM_WARN_ON_ONCE(delta & (PAGE_SIZE - 1));
        delta >>= PAGE_SHIFT;
    }

    /* See __mod_node_page_state */
    preempt_disable_nested();

    x = delta + __this_cpu_read(*p);

    t = __this_cpu_read(pcp->stat_threshold);

    if (unlikely(abs(x) > t)) {
        node_page_state_add(x, pgdat, item);
        x = 0;
    }
    __this_cpu_write(*p, x);

    preempt_enable_nested();
#endif
    PANIC("");
}

void mod_node_page_state(struct pglist_data *pgdat, enum node_stat_item item,
                    long delta)
{
    //mod_node_state(pgdat, item, delta, 0);
    PANIC("");
}

/*
 * Count number of pages "struct page" and "struct page_ext" consume.
 * nr_memmap_boot_pages: # of pages allocated by boot allocator
 * nr_memmap_pages: # of pages that were allocated by buddy allocator
 */
static atomic_long_t nr_memmap_boot_pages = ATOMIC_LONG_INIT(0);
static atomic_long_t nr_memmap_pages = ATOMIC_LONG_INIT(0);

void memmap_boot_pages_add(long delta)
{
    atomic_long_add(delta, &nr_memmap_boot_pages);
}
