#include <linux/timer.h>

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

/**
 * round_jiffies_up - function to round jiffies up to a full second
 * @j: the time in (absolute) jiffies that should be rounded
 *
 * This is the same as round_jiffies() except that it will never
 * round down.  This is useful for timeouts for which the exact time
 * of firing does not matter too much, as long as they don't fire too
 * early.
 */
unsigned long round_jiffies_up(unsigned long j)
{
    //return round_jiffies_common(j, raw_smp_processor_id(), true);
    return 0;
}

ktime_t ktime_get(void)
{
    return 0;
}

/**
 * add_timer - start a timer
 * @timer: the timer to be added
 *
 * The kernel will do a ->function(@timer) callback from the
 * timer interrupt at the ->expires point in the future. The
 * current time is 'jiffies'.
 *
 * The timer's ->expires, ->function fields must be set prior calling this
 * function.
 *
 * Timers with an ->expires field in the past will be executed in the next
 * timer tick.
 */
void add_timer(struct timer_list *timer)
{
    /*
    BUG_ON(timer_pending(timer));
    __mod_timer(timer, timer->expires, MOD_TIMER_NOTPENDING);
    */
}
