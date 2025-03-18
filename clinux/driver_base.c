#include <linux/types.h>
#include <linux/device.h>
#include "booter.h"

extern void foo(void);

void *devm_kmalloc(struct device *dev, size_t size, gfp_t gfp)
{
    sbi_puts("devm_kmalloc ..\n");
    foo();
    sbi_puts("devm_kmalloc ok\n");
    return NULL;
}
