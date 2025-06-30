#include <linux/slab.h>

#include "booter.h"

void __percpu *__alloc_percpu(size_t size, size_t align)
{
    log_error("%s: No impl.", __func__);
    return kmalloc(size, 0);
}
