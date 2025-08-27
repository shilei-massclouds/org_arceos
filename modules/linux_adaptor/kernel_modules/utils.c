#include <linux/string.h>
#include <linux/time64.h>
#include <linux/rbtree.h>
#include <linux/fs.h>
#include <linux/mm.h>
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
    printk("%s: Page(0x%lx): %s\n", __func__, page, reason);
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

/**
 * kvfree() - Free memory.
 * @addr: Pointer to allocated memory.
 *
 * kvfree frees memory allocated by any of vmalloc(), kmalloc() or kvmalloc().
 * It is slightly more efficient to use kfree() or vfree() if you are certain
 * that you know which one to use.
 *
 * Context: Either preemptible task context or not-NMI interrupt.
 */
void kvfree(const void *addr)
{
    log_error("%s: No impl.\n", __func__);
    /*
    if (is_vmalloc_addr(addr))
        vfree(addr);
    else
        kfree(addr);
        */
}

/*
 * Return true if this page is mapped into pagetables.
 * For compound page it returns true if any subpage of compound page is mapped.
 */
bool page_mapped(struct page *page)
{
    int i;

    if (likely(!PageCompound(page)))
        return atomic_read(&page->_mapcount) >= 0;
    page = compound_head(page);
    if (atomic_read(compound_mapcount_ptr(page)) >= 0)
        return true;
    if (PageHuge(page))
        return false;
    for (i = 0; i < compound_nr(page); i++) {
        if (atomic_read(&page[i]._mapcount) >= 0)
            return true;
    }
    return false;
}

/**
 * unmap_mapping_pages() - Unmap pages from processes.
 * @mapping: The address space containing pages to be unmapped.
 * @start: Index of first page to be unmapped.
 * @nr: Number of pages to be unmapped.  0 to unmap to end of file.
 * @even_cows: Whether to unmap even private COWed pages.
 *
 * Unmap the pages in this address space from any userspace process which
 * has them mmaped.  Generally, you want to remove COWed pages as well when
 * a file is being truncated, but not when invalidating pages from the page
 * cache.
 */
void unmap_mapping_pages(struct address_space *mapping, pgoff_t start,
        pgoff_t nr, bool even_cows)
{
    log_error("%s: No impl.", __func__);
}

void workingset_update_node(struct xa_node *node)
{
    log_error("%s: No impl.", __func__);
}

int fprop_local_init_percpu(struct fprop_local_percpu *pl, gfp_t gfp)
{
    log_error("%s: No impl.", __func__);
    return 0;
}


/*
 * Zero means infinite timeout - no checking done:
 */
unsigned long __read_mostly sysctl_hung_task_timeout_secs = CONFIG_DEFAULT_HUNG_TASK_TIMEOUT;
