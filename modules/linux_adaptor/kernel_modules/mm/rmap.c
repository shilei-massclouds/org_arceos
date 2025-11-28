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

#include "adaptor.h"

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

    mapping = folio_mapping(folio);
    if (!mapping)
        return 0;

    rmap_walk(folio, &rwc);

    return cleaned;
}

/*
 * rmap_walk_anon - do something to anonymous page using the object-based
 * rmap method
 * @folio: the folio to be handled
 * @rwc: control variable according to each walk type
 * @locked: caller holds relevant rmap lock
 *
 * Find all the mappings of a folio using the mapping pointer and the vma
 * chains contained in the anon_vma struct it points to.
 */
static void rmap_walk_anon(struct folio *folio,
        struct rmap_walk_control *rwc, bool locked)
{
    PANIC("");
}

/*
 * rmap_walk_file - do something to file page using the object-based rmap method
 * @folio: the folio to be handled
 * @rwc: control variable according to each walk type
 * @locked: caller holds relevant rmap lock
 *
 * Find all the mappings of a folio using the mapping pointer and the vma chains
 * contained in the address_space struct it points to.
 */
static void rmap_walk_file(struct folio *folio,
        struct rmap_walk_control *rwc, bool locked)
{
    struct address_space *mapping = folio_mapping(folio);
    pgoff_t pgoff_start, pgoff_end;
    struct vm_area_struct *vma;

    /*
     * The page lock not only makes sure that page->mapping cannot
     * suddenly be NULLified by truncation, it makes sure that the
     * structure at mapping cannot be freed and reused yet,
     * so we can safely take mapping->i_mmap_rwsem.
     */
    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

    if (!mapping)
        return;

    pgoff_start = folio_pgoff(folio);
    pgoff_end = pgoff_start + folio_nr_pages(folio) - 1;
    if (!locked) {
        if (i_mmap_trylock_read(mapping))
            goto lookup;

        if (rwc->try_lock) {
            rwc->contended = true;
            return;
        }

        i_mmap_lock_read(mapping);
    }
lookup:
    vma_interval_tree_foreach(vma, &mapping->i_mmap,
            pgoff_start, pgoff_end) {
        unsigned long address = vma_address(vma, pgoff_start,
                   folio_nr_pages(folio));

        VM_BUG_ON_VMA(address == -EFAULT, vma);
        cond_resched();

        if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
            continue;

        if (!rwc->rmap_one(folio, vma, address, rwc->arg))
            goto done;
        if (rwc->done && rwc->done(folio))
            goto done;
    }

done:
    if (!locked)
        i_mmap_unlock_read(mapping);
}

void rmap_walk(struct folio *folio, struct rmap_walk_control *rwc)
{
    if (unlikely(folio_test_ksm(folio)))
        rmap_walk_ksm(folio, rwc);
    else if (folio_test_anon(folio))
        rmap_walk_anon(folio, rwc, false);
    else
        rmap_walk_file(folio, rwc, false);
}
