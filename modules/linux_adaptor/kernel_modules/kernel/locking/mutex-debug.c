#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/poison.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/interrupt.h>
#include <linux/debug_locks.h>

#include "mutex.h"

void debug_mutex_init(struct mutex *lock, const char *name,
              struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
    /*
     * Make sure we are not reinitializing a held lock:
     */
    debug_check_no_locks_freed((void *)lock, sizeof(*lock));
    lockdep_init_map_wait(&lock->dep_map, name, key, 0, LD_WAIT_SLEEP);
#endif
    lock->magic = lock;
}
