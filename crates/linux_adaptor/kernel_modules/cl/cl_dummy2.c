#include <linux/cache.h>
#include <linux/cpumask.h>
#include <linux/crash_dump.h>

// mm/percpu.c
unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;

// lib/uuid.c
const u8 guid_index[16] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
const u8 uuid_index[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

// kernel/elfcorehdr.c
/*
 * stores the physical address of elf header of crash image
 *
 * Note: elfcorehdr_addr is not just limited to vmcore. It is also used by
 * is_kdump_kernel() to determine if we are booting after a panic. Hence put
 * it under CONFIG_CRASH_DUMP and not CONFIG_PROC_VMCORE.
 */
unsigned long long elfcorehdr_addr = ELFCORE_ADDR_MAX;
EXPORT_SYMBOL_GPL(elfcorehdr_addr);

// kernel/elfcorehdr.c
/*
 * stores the size of elf header of crash image
 */
unsigned long long elfcorehdr_size;

// mm/debug_page_alloc.c
bool _debug_pagealloc_enabled_early __read_mostly
            = IS_ENABLED(CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT);

// mm/page_alloc.c

/*
 * Array of node states.
 */
nodemask_t node_states[NR_NODE_STATES] __read_mostly = {
    [N_POSSIBLE] = NODE_MASK_ALL,
    [N_ONLINE] = { { [0] = 1UL } },
#ifndef CONFIG_NUMA
    [N_NORMAL_MEMORY] = { { [0] = 1UL } },
#ifdef CONFIG_HIGHMEM
    [N_HIGH_MEMORY] = { { [0] = 1UL } },
#endif
    [N_MEMORY] = { { [0] = 1UL } },
    [N_CPU] = { { [0] = 1UL } },
#endif  /* NUMA */
};

/* movable_zone is the "real" zone pages in ZONE_MOVABLE are taken from */
int movable_zone;

char * const zone_names[MAX_NR_ZONES] = {
#ifdef CONFIG_ZONE_DMA
     "DMA",
#endif
#ifdef CONFIG_ZONE_DMA32
     "DMA32",
#endif
     "Normal",
#ifdef CONFIG_HIGHMEM
     "HighMem",
#endif
     "Movable",
#ifdef CONFIG_ZONE_DEVICE
     "Device",
#endif
};
