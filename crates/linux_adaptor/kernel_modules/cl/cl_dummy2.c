#include <linux/cache.h>
#include <linux/cpumask.h>

// mm/percpu.c
unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;

// lib/uuid.c
const u8 guid_index[16] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
const u8 uuid_index[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
