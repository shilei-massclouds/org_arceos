#include <linux/rmap.h>
#include <linux/ksm.h>

#include "booter.h"

static bool invalid_mkclean_vma(struct vm_area_struct *vma, void *arg)
{
    if (vma->vm_flags & VM_SHARED)
        return false;

    return true;
}

static bool page_mkclean_one(struct page *page, struct vm_area_struct *vma,
                unsigned long address, void *arg)
{
    log_error("%s: No impl.\n", __func__);
    return true;
}

static void rmap_walk_anon(struct page *page, struct rmap_walk_control *rwc,
        bool locked)
{
    log_error("%s: No impl.\n", __func__);
}

static void rmap_walk_file(struct page *page, struct rmap_walk_control *rwc,
        bool locked)
{
    log_error("%s: No impl.\n", __func__);
}

void rmap_walk(struct page *page, struct rmap_walk_control *rwc)
{
    if (unlikely(PageKsm(page)))
        rmap_walk_ksm(page, rwc);
    else if (PageAnon(page))
        rmap_walk_anon(page, rwc, false);
    else
        rmap_walk_file(page, rwc, false);
}

int page_mkclean(struct page *page)
{
    int cleaned = 0;
    struct address_space *mapping;
    struct rmap_walk_control rwc = {
        .arg = (void *)&cleaned,
        .rmap_one = page_mkclean_one,
        .invalid_vma = invalid_mkclean_vma,
    };

    BUG_ON(!PageLocked(page));

    /*
    if (!page_mapped(page))
        return 0;
        */

    mapping = page_mapping(page);
    if (!mapping)
        return 0;

    rmap_walk(page, &rwc);

    return cleaned;
}
