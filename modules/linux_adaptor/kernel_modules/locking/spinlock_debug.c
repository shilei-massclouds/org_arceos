#include <linux/spinlock.h>

void __raw_spin_lock_init(raw_spinlock_t *lock, const char *name,
              struct lock_class_key *key, short inner)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
    /*
     * Make sure we are not reinitializing a held lock:
     */
    debug_check_no_locks_freed((void *)lock, sizeof(*lock));
    lockdep_init_map_wait(&lock->dep_map, name, key, 0, inner);
#endif
    lock->raw_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
    lock->magic = SPINLOCK_MAGIC;
    lock->owner = SPINLOCK_OWNER_INIT;
    lock->owner_cpu = -1;
}
