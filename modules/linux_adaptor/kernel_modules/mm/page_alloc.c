#include <linux/mm.h>

#include "internal.h"
#include "../adaptor.h"

gfp_t gfp_allowed_mask __read_mostly = GFP_BOOT_MASK;

/**
 * alloc_pages_exact - allocate an exact number physically-contiguous pages.
 * @size: the number of bytes to allocate
 * @gfp_mask: GFP flags for the allocation, must not contain __GFP_COMP
 *
 * This function is similar to alloc_pages(), except that it allocates the
 * minimum number of pages to satisfy the request.  alloc_pages() can only
 * allocate memory in power-of-two pages.
 *
 * This function is also limited by MAX_PAGE_ORDER.
 *
 * Memory allocated by this function must be released by free_pages_exact().
 *
 * Return: pointer to the allocated area or %NULL in case of error.
 */
void *alloc_pages_exact_noprof(size_t size, gfp_t gfp_mask)
{
    return cl_alloc_pages(size, PAGE_SIZE);
}

/*
 * This is the 'heart' of the zoned buddy allocator.
 */
struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order,
                      int preferred_nid, nodemask_t *nodemask)
{
    int nr_pages = 1 << order;
    void *va = cl_alloc_pages(PAGE_SIZE * nr_pages, PAGE_SIZE);
    struct page *page = virt_to_page(va);
    // Note: page_type must be inited with UINT_MAX. Check where set it.
    page->page_type = UINT_MAX;
    set_page_count(page, 1);
    return page;
}

struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
        nodemask_t *nodemask)
{
    struct page *page = __alloc_pages_noprof(gfp | __GFP_COMP, order,
                    preferred_nid, nodemask);
    return page_rmappable_folio(page);
}

/**
 * __free_pages - Free pages allocated with alloc_pages().
 * @page: The page pointer returned from alloc_pages().
 * @order: The order of the allocation.
 *
 * This function can free multi-page allocations that are not compound
 * pages.  It does not check that the @order passed in matches that of
 * the allocation, so it is easy to leak memory.  Freeing more memory
 * than was allocated will probably emit a warning.
 *
 * If the last reference to this page is speculative, it will be released
 * by put_page() which only frees the first page of a non-compound
 * allocation.  To prevent the remaining pages from being leaked, we free
 * the subsequent pages here.  If you want to use the page's reference
 * count to decide when to free the allocation, you should allocate a
 * compound page, and use put_page() instead of __free_pages().
 *
 * Context: May be called in interrupt context or while holding a normal
 * spinlock, but not in NMI context or while holding a raw spinlock.
 */
void __free_pages(struct page *page, unsigned int order)
{
    cl_free_pages(page_to_virt(page), (1 << order));
}

/*
 * Free a batch of folios
 */
void free_unref_folios(struct folio_batch *folios)
{
    PANIC("");
}

/*
 * Common helper functions. Never use with __GFP_HIGHMEM because the returned
 * address cannot represent highmem pages. Use alloc_pages and then kmap if
 * you need to access high mem.
 */
unsigned long get_free_pages_noprof(gfp_t gfp_mask, unsigned int order)
{
    struct page *page;

    page = alloc_pages_noprof(gfp_mask & ~__GFP_HIGHMEM, order);
    if (!page)
        return 0;
    return (unsigned long) page_address(page);
}

unsigned long get_zeroed_page_noprof(gfp_t gfp_mask)
{
    return get_free_pages_noprof(gfp_mask | __GFP_ZERO, 0);
}

void free_pages(unsigned long addr, unsigned int order)
{
    if (addr != 0) {
        VM_BUG_ON(!virt_addr_valid((void *)addr));
        __free_pages(virt_to_page((void *)addr), order);
    }
}
