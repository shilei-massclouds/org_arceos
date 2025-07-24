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
