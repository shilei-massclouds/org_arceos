#include <linux/printk.h>
#include "booter.h"

void __raw_spin_lock_init(raw_spinlock_t *lock, const char *name,
              struct lock_class_key *key, short inner)
{
    printk("===> WARN: impl it. (%lx) (%s)\n", (unsigned long)lock, name);
}
