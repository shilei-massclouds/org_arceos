#include <linux/mm.h>

// Note: Just dummy shmem_aops.
static const struct address_space_operations shmem_aops;

bool shmem_mapping(struct address_space *mapping)
{
    return mapping->a_ops == &shmem_aops;
}
