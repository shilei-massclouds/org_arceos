#include "booter.h"

void __init_waitqueue_head(struct wait_queue_head *wq_head, const char *name, struct lock_class_key *key)
{
    log_debug("%s: No impl.", __func__);
}
