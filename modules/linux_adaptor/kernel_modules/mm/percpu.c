#include <linux/percpu.h>
#include <linux/slab.h>

#ifndef CONFIG_HAVE_SETUP_PER_CPU_AREA
/*
 * Generic SMP percpu area setup.
 *
 * The embedding helper is used because its behavior closely resembles
 * the original non-dynamic generic percpu area setup.  This is
 * important because many archs have addressing restrictions and might
 * fail if the percpu area is located far away from the previous
 * location.  As an added bonus, in non-NUMA cases, embedding is
 * generally a good idea TLB-wise because percpu area can piggy back
 * on the physical linear memory mapping which uses large page
 * mappings on applicable archs.
 */
unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;

void __init setup_per_cpu_areas(void)
{
    pr_err("%s: !!!IMPORTANT!!! No impl.", __func__);
}

#endif

void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved,
                 gfp_t gfp)
{
    pr_err("!!!IMPORTANT!!! %s: No impl.", __func__);
    return kmalloc(size, 0);
}
