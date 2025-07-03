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
