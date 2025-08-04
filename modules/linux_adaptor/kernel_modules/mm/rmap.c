#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/huge_mm.h>
#include <linux/backing-dev.h>
#include <linux/page_idle.h>
#include <linux/memremap.h>
#include <linux/userfaultfd_k.h>
#include <linux/mm_inline.h>
#include <linux/oom.h>

#include <asm/tlbflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/tlb.h>
#include <trace/events/migrate.h>

#include "internal.h"

#include "../adaptor.h"

static int page_vma_mkclean_one(struct page_vma_mapped_walk *pvmw)
{
    PANIC("");
}

static bool page_mkclean_one(struct folio *folio, struct vm_area_struct *vma,
                 unsigned long address, void *arg)
{
    DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, PVMW_SYNC);
    int *cleaned = arg;

    *cleaned += page_vma_mkclean_one(&pvmw);

    return true;
}

static bool invalid_mkclean_vma(struct vm_area_struct *vma, void *arg)
{
    if (vma->vm_flags & VM_SHARED)
        return false;

    return true;
}

int folio_mkclean(struct folio *folio)
{
    int cleaned = 0;
    struct address_space *mapping;
    struct rmap_walk_control rwc = {
        .arg = (void *)&cleaned,
        .rmap_one = page_mkclean_one,
        .invalid_vma = invalid_mkclean_vma,
    };

    BUG_ON(!folio_test_locked(folio));

    if (!folio_mapped(folio))
        return 0;

#if 0
    mapping = folio_mapping(folio);
    if (!mapping)
        return 0;

    rmap_walk(folio, &rwc);

    return cleaned;
#endif
    PANIC("");
}
