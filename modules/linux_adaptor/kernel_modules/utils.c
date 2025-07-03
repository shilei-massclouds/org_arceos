#include <linux/string.h>
#include <linux/time64.h>
#include <linux/rbtree.h>
#include <linux/fs.h>
#include <linux/pipe_fs_i.h>

#include "booter.h"

// Dummy defined in fs/splice.
const struct pipe_buf_operations default_pipe_buf_ops;

void get_random_bytes(void *buf, int nbytes)
{
    memset(buf, 1, nbytes);
}

time64_t ktime_get_real_seconds(void)
{
    return 0;
}

int ___ratelimit(struct ratelimit_state *rs, const char *func)
{
    log_error("%s: No impl.", __func__);
    return 0;
}

void __might_fault(const char *file, int line)
{
    log_error("%s: No impl.", __func__);
}

void dump_page(struct page *page, const char *reason)
{
    log_error("%s: Page(0x%lx): %s\n", __func__, page, reason);
    booter_panic("No impl.");
}

/**
 * rcu_sync_init() - Initialize an rcu_sync structure
 * @rsp: Pointer to rcu_sync structure to be initialized
 */
void rcu_sync_init(struct rcu_sync *rsp)
{
    memset(rsp, 0, sizeof(*rsp));
    init_waitqueue_head(&rsp->gp_wait);
}

/**
 * errseq_check() - Has an error occurred since a particular sample point?
 * @eseq: Pointer to errseq_t value to be checked.
 * @since: Previously-sampled errseq_t from which to check.
 *
 * Grab the value that eseq points to, and see if it has changed @since
 * the given value was sampled. The @since value is not advanced, so there
 * is no need to mark the value as seen.
 *
 * Return: The latest error set in the errseq_t or 0 if it hasn't changed.
 */
int errseq_check(errseq_t *eseq, errseq_t since)
{
    errseq_t cur = READ_ONCE(*eseq);

    if (likely(cur == since))
        return 0;
    return -(cur & MAX_ERRNO);
}

struct address_space *page_mapping(struct page *page)
{
    struct address_space *mapping;

    page = compound_head(page);

    /* This happens if someone calls flush_dcache_page on slab page */
    if (unlikely(PageSlab(page)))
        return NULL;

    /*
    if (unlikely(PageSwapCache(page))) {
        swp_entry_t entry;

        entry.val = page_private(page);
        return swap_address_space(entry);
    }
    */

    mapping = page->mapping;
    if ((unsigned long)mapping & PAGE_MAPPING_ANON)
        return NULL;

    return (void *)((unsigned long)mapping & ~PAGE_MAPPING_FLAGS);
}

/*
 * Zero means infinite timeout - no checking done:
 */
unsigned long __read_mostly sysctl_hung_task_timeout_secs = CONFIG_DEFAULT_HUNG_TASK_TIMEOUT;
