#include "booter.h"

void init_timer_key(struct timer_list *timer,
            void (*func)(struct timer_list *), unsigned int flags,
            const char *name, struct lock_class_key *key)
{
    log_error("%s: No impl.", __func__);
}

int register_shrinker(struct shrinker *shrinker)
{
    log_error("%s: No impl.", __func__);
}
