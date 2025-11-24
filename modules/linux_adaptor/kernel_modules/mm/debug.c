#include <linux/mm.h>

#include "adaptor.h"

static bool page_init_poisoning __read_mostly = true;

void dump_page(const struct page *page, const char *reason)
{
    pr_err("%s: Page(0x%lx): %s", __func__, page, reason);
}

void page_init_poison(struct page *page, size_t size)
{
    if (page_init_poisoning)
        memset(page, PAGE_POISON_PATTERN, size);
}
