#include <linux/types.h>
#include "booter.h"

void *kmalloc(size_t size, gfp_t flags)
{
    return cl_rust_alloc(size, 8);
}
