#include <linux/mm.h>
#include <linux/page-isolation.h>

unsigned int _debug_guardpage_minorder;

bool _debug_pagealloc_enabled_early __read_mostly
            = IS_ENABLED(CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT);
EXPORT_SYMBOL(_debug_pagealloc_enabled_early);
DEFINE_STATIC_KEY_FALSE(_debug_pagealloc_enabled);
EXPORT_SYMBOL(_debug_pagealloc_enabled);

DEFINE_STATIC_KEY_FALSE(_debug_guardpage_enabled);

void __clear_page_guard(struct zone *zone, struct page *page, unsigned int order)
{
    __ClearPageGuard(page);
    set_page_private(page, 0);
}
