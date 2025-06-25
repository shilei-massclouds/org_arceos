#include <linux/fs.h>
#include "booter.h"

void __put_page(struct page *page)
{
    log_debug("%s: No impl.", __func__);
}
