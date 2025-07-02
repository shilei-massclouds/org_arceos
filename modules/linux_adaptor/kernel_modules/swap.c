#include <linux/fs.h>
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
