#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>

#include "booter.h"

void __put_page(struct page *page)
{
    log_debug("%s: No impl.", __func__);
}

/*
 * Mark a page as having seen activity.
 *
 * inactive,unreferenced    ->  inactive,referenced
 * inactive,referenced      ->  active,unreferenced
 * active,unreferenced      ->  active,referenced
 *
 * When a newly allocated page is not yet visible, so safe for non-atomic ops,
 * __SetPageReferenced(page) may be substituted for mark_page_accessed(page).
 */
void mark_page_accessed(struct page *page)
{
    log_debug("%s: No impl.", __func__);
}

unsigned pagevec_lookup_range_tag(struct pagevec *pvec,
        struct address_space *mapping, pgoff_t *index, pgoff_t end,
        xa_mark_t tag)
{
    pvec->nr = find_get_pages_range_tag(mapping, index, end, tag,
                    PAGEVEC_SIZE, pvec->pages);
    return pagevec_count(pvec);
}

void lru_add_drain(void)
{
    /*
    local_lock(&lru_pvecs.lock);
    lru_add_drain_cpu(smp_processor_id());
    local_unlock(&lru_pvecs.lock);
    */
    log_error("%s: No impl.\n", __func__);
}

/**
 * release_pages - batched put_page()
 * @pages: array of pages to release
 * @nr: number of pages
 *
 * Decrement the reference count on all the pages in @pages.  If it
 * fell to zero, remove the page from the LRU and free it.
 */
void release_pages(struct page **pages, int nr)
{
    log_error("%s: No impl.\n", __func__);
}

/*
 * The pages which we're about to release may be in the deferred lru-addition
 * queues.  That would prevent them from really being freed right now.  That's
 * OK from a correctness point of view but is inefficient - those pages may be
 * cache-warm and we want to give them back to the page allocator ASAP.
 *
 * So __pagevec_release() will drain those queues here.  __pagevec_lru_add()
 * and __pagevec_lru_add_active() call release_pages() directly to avoid
 * mutual recursion.
 */
void __pagevec_release(struct pagevec *pvec)
{
    if (!pvec->percpu_pvec_drained) {
        lru_add_drain();
        pvec->percpu_pvec_drained = true;
    }
    release_pages(pvec->pages, pagevec_count(pvec));
    pagevec_reinit(pvec);
}
