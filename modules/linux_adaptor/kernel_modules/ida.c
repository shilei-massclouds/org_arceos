#include <linux/types.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "booter.h"
#include "base.h"

int ida_alloc_range(struct ida *ida, unsigned int min, unsigned int max,
            gfp_t gfp)
{
    printk("%s: %d-%d\n", __func__, min, max);
    return min;
}
