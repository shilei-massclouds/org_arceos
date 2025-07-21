#include <linux/mm.h>

#include "../adaptor.h"

void dump_page(const struct page *page, const char *reason)
{
    pr_err("%s: Page(0x%lx): %s", __func__, page, reason);
}
