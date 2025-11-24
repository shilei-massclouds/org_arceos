// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/page_alloc.c
 *
 *  Manages the free list, the system allocates free pages here.
 *  Note that kmalloc() lives in slab.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 *  Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
 *          (lots of bits borrowed from Ingo Molnar & Andrew Morton)
 */

#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kasan.h>
#include <linux/kmsan.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/ratelimit.h>
#include <linux/oom.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/pagevec.h>
#include <linux/memory_hotplug.h>
#include <linux/nodemask.h>
#include <linux/vmstat.h>
#include <linux/fault-inject.h>
#include <linux/compaction.h>
#include <trace/events/kmem.h>
#include <trace/events/oom.h>
#include <linux/prefetch.h>
#include <linux/mm_inline.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/sched/mm.h>
#include <linux/page_owner.h>
#include <linux/page_table_check.h>
#include <linux/memcontrol.h>
#include <linux/ftrace.h>
#include <linux/lockdep.h>
#include <linux/psi.h>
#include <linux/khugepaged.h>
#include <linux/delayacct.h>
#include <linux/cacheinfo.h>
#include <linux/pgalloc_tag.h>
#include <asm/div64.h>
#include "internal.h"
#include "shuffle.h"
#include "page_reporting.h"

#include "adaptor.h"

/*
 * On SMP, spin_trylock is sufficient protection.
 * On PREEMPT_RT, spin_trylock is equivalent on both SMP and UP.
 */
#define pcp_trylock_prepare(flags)  do { } while (0)
#define pcp_trylock_finish(flag)    do { } while (0)

#define pcpu_task_pin()     preempt_disable()
#define pcpu_task_unpin()   preempt_enable()

/*
 * Generic helper to lookup and a per-cpu variable with an embedded spinlock.
 * Return value should be used with equivalent unlock helper.
 */
#define pcpu_spin_lock(type, member, ptr)               \
({                                  \
    type *_ret;                         \
    pcpu_task_pin();                        \
    _ret = this_cpu_ptr(ptr);                   \
    spin_lock(&_ret->member);                   \
    _ret;                               \
})

#define pcpu_spin_trylock(type, member, ptr)                \
({                                  \
    type *_ret;                         \
    pcpu_task_pin();                        \
    _ret = this_cpu_ptr(ptr);                   \
    if (!spin_trylock(&_ret->member)) {             \
        pcpu_task_unpin();                  \
        _ret = NULL;                        \
    }                               \
    _ret;                               \
})

#define pcpu_spin_unlock(member, ptr)                   \
({                                  \
    spin_unlock(&ptr->member);                  \
    pcpu_task_unpin();                      \
})

/* struct per_cpu_pages specific helpers. */
#define pcp_spin_lock(ptr)                      \
    pcpu_spin_lock(struct per_cpu_pages, lock, ptr)

#define pcp_spin_trylock(ptr)                       \
    pcpu_spin_trylock(struct per_cpu_pages, lock, ptr)

#define pcp_spin_unlock(ptr)                        \
    pcpu_spin_unlock(lock, ptr)

/* No special request */
#define FPI_NONE        ((__force fpi_t)0)

/*
 * Skip free page reporting notification for the (possibly merged) page.
 * This does not hinder free page reporting from grabbing the page,
 * reporting it and marking it "reported" -  it only skips notifying
 * the free page reporting infrastructure about a newly freed page. For
 * example, used when temporarily pulling a page from a freelist and
 * putting it back unmodified.
 */
#define FPI_SKIP_REPORT_NOTIFY  ((__force fpi_t)BIT(0))

/*
 * Place the (possibly merged) page to the tail of the freelist. Will ignore
 * page shuffling (relevant code - e.g., memory onlining - is expected to
 * shuffle the whole zone).
 *
 * Note: No code should rely on this flag for correctness - it's purely
 *       to allow for optimizations when handing back either fresh pages
 *       (memory onlining) or untouched pages (page isolation, free page
 *       reporting).
 */
#define FPI_TO_TAIL     ((__force fpi_t)BIT(1))

/* Free Page Internal flags: for internal, non-pcp variants of free_pages(). */
typedef int __bitwise fpi_t;

gfp_t gfp_allowed_mask __read_mostly = GFP_BOOT_MASK;

static inline bool deferred_pages_enabled(void)
{
    return false;
}

static inline bool _deferred_grow_zone(struct zone *zone, unsigned int order)
{
    return false;
}

static __always_inline int get_pfnblock_migratetype(const struct page *page,
                    unsigned long pfn)
{
    return get_pfnblock_flags_mask(page, pfn, MIGRATETYPE_MASK);
}

static inline void set_buddy_order(struct page *page, unsigned int order)
{
    set_page_private(page, order);
    __SetPageBuddy(page);
}

static inline bool is_check_pages_enabled(void)
{
    return static_branch_unlikely(&check_pages_enabled);
}

#ifdef CONFIG_COMPACTION
static inline struct capture_control *task_capc(struct zone *zone)
{
    struct capture_control *capc = current->capture_control;

    return unlikely(capc) &&
        !(current->flags & PF_KTHREAD) &&
        !capc->page &&
        capc->cc->zone == zone ? capc : NULL;
}

static inline bool
compaction_capture(struct capture_control *capc, struct page *page,
           int order, int migratetype)
{
    if (!capc || order != capc->cc->order)
        return false;

    /* Do not accidentally pollute CMA or isolated regions*/
    if (is_migrate_cma(migratetype) ||
        is_migrate_isolate(migratetype))
        return false;

    /*
     * Do not let lower order allocations pollute a movable pageblock
     * unless compaction is also requesting movable pages.
     * This might let an unmovable request use a reclaimable pageblock
     * and vice-versa but no more than normal fallback logic which can
     * have trouble finding a high-order free page.
     */
    if (order < pageblock_order && migratetype == MIGRATE_MOVABLE &&
        capc->cc->migratetype != MIGRATE_MOVABLE)
        return false;

    capc->page = page;
    return true;
}

#else

static inline struct capture_control *task_capc(struct zone *zone)
{
    return NULL;
}

static inline bool
compaction_capture(struct capture_control *capc, struct page *page,
           int order, int migratetype)
{
    return false;
}
#endif /* CONFIG_COMPACTION */

#ifdef CONFIG_DEBUG_VM
static int page_outside_zone_boundaries(struct zone *zone, struct page *page)
{
    int ret;
    unsigned seq;
    unsigned long pfn = page_to_pfn(page);
    unsigned long sp, start_pfn;

    do {
        seq = zone_span_seqbegin(zone);
        start_pfn = zone->zone_start_pfn;
        sp = zone->spanned_pages;
        ret = !zone_spans_pfn(zone, pfn);
    } while (zone_span_seqretry(zone, seq));

    if (ret)
        pr_err("page 0x%lx outside node %d zone %s [ 0x%lx - 0x%lx ]\n",
            pfn, zone_to_nid(zone), zone->name,
            start_pfn, start_pfn + sp);

    return ret;
}

/*
 * Temporary debugging check for pages not lying within a given zone.
 */
static bool __maybe_unused bad_range(struct zone *zone, struct page *page)
{
    if (page_outside_zone_boundaries(zone, page))
        return true;
    if (zone != page_zone(page))
        return true;

    return false;
}
#else
static inline bool __maybe_unused bad_range(struct zone *zone, struct page *page)
{
    return false;
}
#endif

static inline void account_freepages(struct zone *zone, int nr_pages,
                     int migratetype)
{
    lockdep_assert_held(&zone->lock);

    if (is_migrate_isolate(migratetype))
        return;

    __mod_zone_page_state(zone, NR_FREE_PAGES, nr_pages);

    if (is_migrate_cma(migratetype))
        __mod_zone_page_state(zone, NR_FREE_CMA_PAGES, nr_pages);
    else if (is_migrate_highatomic(migratetype))
        WRITE_ONCE(zone->nr_free_highatomic,
               zone->nr_free_highatomic + nr_pages);
}

/*
 * If this is less than the 2nd largest possible page, check if the buddy
 * of the next-higher order is free. If it is, it's possible
 * that pages are being freed that will coalesce soon. In case,
 * that is happening, add the free page to the tail of the list
 * so it's less likely to be used soon and more likely to be merged
 * as a 2-level higher order page
 */
static inline bool
buddy_merge_likely(unsigned long pfn, unsigned long buddy_pfn,
           struct page *page, unsigned int order)
{
    unsigned long higher_page_pfn;
    struct page *higher_page;

    if (order >= MAX_PAGE_ORDER - 1)
        return false;

    higher_page_pfn = buddy_pfn & pfn;
    higher_page = page + (higher_page_pfn - pfn);

    return find_buddy_page_pfn(higher_page, higher_page_pfn, order + 1,
            NULL) != NULL;
}

static inline void __del_page_from_free_list(struct page *page, struct zone *zone,
                         unsigned int order, int migratetype)
{
        VM_WARN_ONCE(get_pageblock_migratetype(page) != migratetype,
             "page type is %lu, passed migratetype is %d (nr=%d)\n",
             get_pageblock_migratetype(page), migratetype, 1 << order);

    /* clear reported state and update reported page count */
    if (page_reported(page))
        __ClearPageReported(page);

    list_del(&page->buddy_list);
    __ClearPageBuddy(page);
    set_page_private(page, 0);
    zone->free_area[order].nr_free--;
}

/* Used for pages not on another list */
static inline void __add_to_free_list(struct page *page, struct zone *zone,
                      unsigned int order, int migratetype,
                      bool tail)
{
    struct free_area *area = &zone->free_area[order];

    VM_WARN_ONCE(get_pageblock_migratetype(page) != migratetype,
             "page type is %lu, passed migratetype is %d (nr=%d)\n",
             get_pageblock_migratetype(page), migratetype, 1 << order);

    if (tail)
        list_add_tail(&page->buddy_list, &area->free_list[migratetype]);
    else
        list_add(&page->buddy_list, &area->free_list[migratetype]);
    area->nr_free++;
}

static inline void __free_one_page(struct page *page,
        unsigned long pfn,
        struct zone *zone, unsigned int order,
        int migratetype, fpi_t fpi_flags)
{
    struct capture_control *capc = task_capc(zone);
    unsigned long buddy_pfn = 0;
    unsigned long combined_pfn;
    struct page *buddy;
    bool to_tail;

    VM_BUG_ON(!zone_is_initialized(zone));
    VM_BUG_ON_PAGE(page->flags & PAGE_FLAGS_CHECK_AT_PREP, page);

    VM_BUG_ON(migratetype == -1);
    VM_BUG_ON_PAGE(pfn & ((1 << order) - 1), page);
    VM_BUG_ON_PAGE(bad_range(zone, page), page);

    account_freepages(zone, 1 << order, migratetype);

    while (order < MAX_PAGE_ORDER) {
        int buddy_mt = migratetype;

        if (compaction_capture(capc, page, order, migratetype)) {
            account_freepages(zone, -(1 << order), migratetype);
            return;
        }

        buddy = find_buddy_page_pfn(page, pfn, order, &buddy_pfn);
        if (!buddy)
            goto done_merging;

        if (unlikely(order >= pageblock_order)) {
            /*
             * We want to prevent merge between freepages on pageblock
             * without fallbacks and normal pageblock. Without this,
             * pageblock isolation could cause incorrect freepage or CMA
             * accounting or HIGHATOMIC accounting.
             */
            buddy_mt = get_pfnblock_migratetype(buddy, buddy_pfn);

            if (migratetype != buddy_mt &&
                (!migratetype_is_mergeable(migratetype) ||
                 !migratetype_is_mergeable(buddy_mt)))
                goto done_merging;
        }

        /*
         * Our buddy is free or it is CONFIG_DEBUG_PAGEALLOC guard page,
         * merge with it and move up one order.
         */
        if (page_is_guard(buddy))
            clear_page_guard(zone, buddy, order);
        else
            __del_page_from_free_list(buddy, zone, order, buddy_mt);

        if (unlikely(buddy_mt != migratetype)) {
            /*
             * Match buddy type. This ensures that an
             * expand() down the line puts the sub-blocks
             * on the right freelists.
             */
            set_pageblock_migratetype(buddy, migratetype);
        }

        combined_pfn = buddy_pfn & pfn;
        page = page + (combined_pfn - pfn);
        pfn = combined_pfn;
        order++;
    }

done_merging:
    set_buddy_order(page, order);

    if (fpi_flags & FPI_TO_TAIL)
        to_tail = true;
    else if (is_shuffle_order(order))
        to_tail = shuffle_pick_tail();
    else
        to_tail = buddy_merge_likely(pfn, buddy_pfn, page, order);

    __add_to_free_list(page, zone, order, migratetype, to_tail);

    /* Notify page reporting subsystem of freed page */
    if (!(fpi_flags & FPI_SKIP_REPORT_NOTIFY))
        page_reporting_notify_free(order);
}

/* Split a multi-block free page into its individual pageblocks. */
static void split_large_buddy(struct zone *zone, struct page *page,
                  unsigned long pfn, int order, fpi_t fpi)
{
    unsigned long end = pfn + (1 << order);

    VM_WARN_ON_ONCE(!IS_ALIGNED(pfn, 1 << order));
    /* Caller removed page from freelist, buddy info cleared! */
    VM_WARN_ON_ONCE(PageBuddy(page));

    if (order > pageblock_order)
        order = pageblock_order;

    do {
        int mt = get_pfnblock_migratetype(page, pfn);

        __free_one_page(page, pfn, zone, order, mt, fpi);
        pfn += 1 << order;
        if (pfn == end)
            break;
        page = pfn_to_page(pfn);
    } while (1);
}

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

static inline bool should_skip_init(gfp_t flags)
{
    /* Don't skip, if hardware tag-based KASAN is not enabled. */
    if (!kasan_hw_tags_enabled())
        return false;

    /* For hardware tag-based KASAN, skip if requested. */
    return (flags & __GFP_SKIP_ZERO);
}

static inline bool should_skip_kasan_unpoison(gfp_t flags)
{
    /* Don't skip if a software KASAN mode is enabled. */
    if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
        IS_ENABLED(CONFIG_KASAN_SW_TAGS))
        return false;

    /* Skip, if hardware tag-based KASAN is not enabled. */
    if (!kasan_hw_tags_enabled())
        return true;

    /*
     * With hardware tag-based KASAN enabled, skip if this has been
     * requested via __GFP_SKIP_KASAN.
     */
    return flags & __GFP_SKIP_KASAN;
}

inline void post_alloc_hook(struct page *page, unsigned int order,
                gfp_t gfp_flags)
{
    bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
            !should_skip_init(gfp_flags);
    bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
    int i;

    set_page_private(page, 0);
    set_page_refcounted(page);

    arch_alloc_page(page, order);
    debug_pagealloc_map_pages(page, 1 << order);

    /*
     * Page unpoisoning must happen before memory initialization.
     * Otherwise, the poison pattern will be overwritten for __GFP_ZERO
     * allocations and the page unpoisoning code will complain.
     */
    kernel_unpoison_pages(page, 1 << order);

    /*
     * As memory initialization might be integrated into KASAN,
     * KASAN unpoisoning and memory initializion code must be
     * kept together to avoid discrepancies in behavior.
     */

    /*
     * If memory tags should be zeroed
     * (which happens only when memory should be initialized as well).
     */
    if (zero_tags) {
        /* Initialize both memory and memory tags. */
        for (i = 0; i != 1 << order; ++i)
            tag_clear_highpage(page + i);

        /* Take note that memory was initialized by the loop above. */
        init = false;
    }
    if (!should_skip_kasan_unpoison(gfp_flags) &&
        kasan_unpoison_pages(page, order, init)) {
        /* Take note that memory was initialized by KASAN. */
        if (kasan_has_integrated_init())
            init = false;
    } else {
        /*
         * If memory tags have not been set by KASAN, reset the page
         * tags to ensure page_address() dereferencing does not fault.
         */
        for (i = 0; i != 1 << order; ++i)
            page_kasan_tag_reset(page + i);
    }
#if 0
    /* If memory is still not initialized, initialize it now. */
    if (init)
        kernel_init_pages(page, 1 << order);
#endif

    set_page_owner(page, order, gfp_flags);
    page_table_check_alloc(page, order);
    pgalloc_tag_add(page, current, 1 << order);
}

static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
                            unsigned int alloc_flags)
{
    post_alloc_hook(page, order, gfp_flags);

    if (order && (gfp_flags & __GFP_COMP))
        prep_compound_page(page, order);

#if 0
    /*
     * page is set pfmemalloc when ALLOC_NO_WATERMARKS was necessary to
     * allocate the page. The expectation is that the caller is taking
     * steps that will free more memory. The caller should avoid the page
     * being used for !PFMEMALLOC purposes.
     */
    if (alloc_flags & ALLOC_NO_WATERMARKS)
        set_page_pfmemalloc(page);
    else
        clear_page_pfmemalloc(page);
#endif
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
    memset(page, 0, sizeof(struct page));
    prep_new_page(page, order, gfp, 0 /* alloc_flags */);
    // Note: all pages belone to node-0 and DMA32
    set_page_node(page, 0);
    set_page_zone(page, ZONE_DMA32);

    // Note: Consider to implement __init_single_page
    //NOTE: Fix _mapcount.
    //atomic_set(&page->_mapcount, -1);
    INIT_LIST_HEAD(&page->lru);

    //set_page_count(page, 1);
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

static inline bool pcp_allowed_order(unsigned int order)
{
    if (order <= PAGE_ALLOC_COSTLY_ORDER)
        return true;
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
    if (order == HPAGE_PMD_ORDER)
        return true;
#endif
    return false;
}

static void free_one_page(struct zone *zone, struct page *page,
              unsigned long pfn, unsigned int order,
              fpi_t fpi_flags)
{
    unsigned long flags;

    spin_lock_irqsave(&zone->lock, flags);
    split_large_buddy(zone, page, pfn, order, fpi_flags);
    spin_unlock_irqrestore(&zone->lock, flags);

    __count_vm_events(PGFREE, 1 << order);
}

static inline unsigned int order_to_pindex(int migratetype, int order)
{
    bool __maybe_unused movable;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
    if (order > PAGE_ALLOC_COSTLY_ORDER) {
        VM_BUG_ON(order != HPAGE_PMD_ORDER);

        movable = migratetype == MIGRATE_MOVABLE;

        return NR_LOWORDER_PCP_LISTS + movable;
    }
#else
    VM_BUG_ON(order > PAGE_ALLOC_COSTLY_ORDER);
#endif

    return (MIGRATE_PCPTYPES * order) + migratetype;
}

static int nr_pcp_high(struct per_cpu_pages *pcp, struct zone *zone,
               int batch, bool free_high)
{
    PANIC("");
}

/*
 * Frees a number of pages from the PCP lists
 * Assumes all pages on list are in same zone.
 * count is the number of pages to free.
 */
static void free_pcppages_bulk(struct zone *zone, int count,
                    struct per_cpu_pages *pcp,
                    int pindex)
{
    PANIC("");
}

static int nr_pcp_free(struct per_cpu_pages *pcp, int batch, int high, bool free_high)
{
    int min_nr_free, max_nr_free;

    /* Free as much as possible if batch freeing high-order pages. */
    if (unlikely(free_high))
        return min(pcp->count, batch << CONFIG_PCP_BATCH_SCALE_MAX);

    /* Check for PCP disabled or boot pageset */
    if (unlikely(high < batch))
        return 1;

    /* Leave at least pcp->batch pages on the list */
    min_nr_free = batch;
    max_nr_free = high - batch;

    /*
     * Increase the batch number to the number of the consecutive
     * freed pages to reduce zone lock contention.
     */
    batch = clamp_t(int, pcp->free_count, min_nr_free, max_nr_free);

    return batch;
}

static void free_unref_page_commit(struct zone *zone, struct per_cpu_pages *pcp,
                   struct page *page, int migratetype,
                   unsigned int order)
{
    int high, batch;
    int pindex;
    bool free_high = false;

    /*
     * On freeing, reduce the number of pages that are batch allocated.
     * See nr_pcp_alloc() where alloc_factor is increased for subsequent
     * allocations.
     */
    pcp->alloc_factor >>= 1;
    __count_vm_events(PGFREE, 1 << order);
    pindex = order_to_pindex(migratetype, order);
    list_add(&page->pcp_list, &pcp->lists[pindex]);
    pcp->count += 1 << order;

    batch = READ_ONCE(pcp->batch);
    /*
     * As high-order pages other than THP's stored on PCP can contribute
     * to fragmentation, limit the number stored when PCP is heavily
     * freeing without allocation. The remainder after bulk freeing
     * stops will be drained from vmstat refresh context.
     */
    if (order && order <= PAGE_ALLOC_COSTLY_ORDER) {
        free_high = (pcp->free_count >= batch &&
                 (pcp->flags & PCPF_PREV_FREE_HIGH_ORDER) &&
                 (!(pcp->flags & PCPF_FREE_HIGH_BATCH) ||
                  pcp->count >= READ_ONCE(batch)));
        pcp->flags |= PCPF_PREV_FREE_HIGH_ORDER;
    } else if (pcp->flags & PCPF_PREV_FREE_HIGH_ORDER) {
        pcp->flags &= ~PCPF_PREV_FREE_HIGH_ORDER;
    }
    if (pcp->free_count < (batch << CONFIG_PCP_BATCH_SCALE_MAX))
        pcp->free_count += (1 << order);
    high = nr_pcp_high(pcp, zone, batch, free_high);
    if (pcp->count >= high) {
        free_pcppages_bulk(zone, nr_pcp_free(pcp, batch, high, free_high),
                   pcp, pindex);
        if (test_bit(ZONE_BELOW_HIGH, &zone->flags) &&
            zone_watermark_ok(zone, 0, high_wmark_pages(zone),
                      ZONE_MOVABLE, 0))
            clear_bit(ZONE_BELOW_HIGH, &zone->flags);
    }

    PANIC("");
}

/*
 * Free a batch of folios
 */
void free_unref_folios(struct folio_batch *folios)
{
    unsigned long __maybe_unused UP_flags;
    struct per_cpu_pages *pcp = NULL;
    struct zone *locked_zone = NULL;
    int i, j;

    /* Prepare folios for freeing */
    for (i = 0, j = 0; i < folios->nr; i++) {
        struct folio *folio = folios->folios[i];
        unsigned long pfn = folio_pfn(folio);
        unsigned int order = folio_order(folio);

        if (!free_pages_prepare(&folio->page, order))
            continue;
        /*
         * Free orders not handled on the PCP directly to the
         * allocator.
         */
        if (!pcp_allowed_order(order)) {
            free_one_page(folio_zone(folio), &folio->page,
                      pfn, order, FPI_NONE);
            continue;
        }
        folio->private = (void *)(unsigned long)order;
        if (j != i)
            folios->folios[j] = folio;
        j++;
    }
    folios->nr = j;

    for (i = 0; i < folios->nr; i++) {
        struct folio *folio = folios->folios[i];
        struct zone *zone = folio_zone(folio);
        unsigned long pfn = folio_pfn(folio);
        unsigned int order = (unsigned long)folio->private;
        int migratetype;

        folio->private = NULL;
        migratetype = get_pfnblock_migratetype(&folio->page, pfn);

    printk("%s: step1\n", __func__);
        /* Different zone requires a different pcp lock */
        if (zone != locked_zone ||
            is_migrate_isolate(migratetype)) {
            if (pcp) {
                pcp_spin_unlock(pcp);
                pcp_trylock_finish(UP_flags);
                locked_zone = NULL;
                pcp = NULL;
            }

    printk("%s: step2\n", __func__);
            /*
             * Free isolated pages directly to the
             * allocator, see comment in free_unref_page.
             */
            if (is_migrate_isolate(migratetype)) {
                free_one_page(zone, &folio->page, pfn,
                          order, FPI_NONE);
                continue;
            }

    printk("%s: step3\n", __func__);
            /*
             * trylock is necessary as folios may be getting freed
             * from IRQ or SoftIRQ context after an IO completion.
             */
            pcp_trylock_prepare(UP_flags);
            pcp = pcp_spin_trylock(zone->per_cpu_pageset);
            if (unlikely(!pcp)) {
                pcp_trylock_finish(UP_flags);
                free_one_page(zone, &folio->page, pfn,
                          order, FPI_NONE);
                continue;
            }
            locked_zone = zone;
        }

    printk("%s: stepN\n", __func__);
        /*
         * Non-isolated types over MIGRATE_PCPTYPES get added
         * to the MIGRATE_MOVABLE pcp list.
         */
        if (unlikely(migratetype >= MIGRATE_PCPTYPES))
            migratetype = MIGRATE_MOVABLE;

        trace_mm_page_free_batched(&folio->page);
        free_unref_page_commit(zone, pcp, &folio->page, migratetype,
                order);
    }

    if (pcp) {
        pcp_spin_unlock(pcp);
        pcp_trylock_finish(UP_flags);
    }
    folio_batch_reinit(folios);
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

/*
 * Skip KASAN memory poisoning when either:
 *
 * 1. For generic KASAN: deferred memory initialization has not yet completed.
 *    Tag-based KASAN modes skip pages freed via deferred memory initialization
 *    using page tags instead (see below).
 * 2. For tag-based KASAN modes: the page has a match-all KASAN tag, indicating
 *    that error detection is disabled for accesses via the page address.
 *
 * Pages will have match-all tags in the following circumstances:
 *
 * 1. Pages are being initialized for the first time, including during deferred
 *    memory init; see the call to page_kasan_tag_reset in __init_single_page.
 * 2. The allocation was not unpoisoned due to __GFP_SKIP_KASAN, with the
 *    exception of pages unpoisoned by kasan_unpoison_vmalloc.
 * 3. The allocation was excluded from being checked due to sampling,
 *    see the call to kasan_unpoison_pages.
 *
 * Poisoning pages during deferred memory init will greatly lengthen the
 * process and cause problem in large memory systems as the deferred pages
 * initialization is done with interrupt disabled.
 *
 * Assuming that there will be no reference to those newly initialized
 * pages before they are ever allocated, this should have no effect on
 * KASAN memory tracking as the poison will be properly inserted at page
 * allocation time. The only corner case is when pages are allocated by
 * on-demand allocation and then freed again before the deferred pages
 * initialization is done, but this is not likely to happen.
 */
static inline bool should_skip_kasan_poison(struct page *page)
{
    if (IS_ENABLED(CONFIG_KASAN_GENERIC))
        return deferred_pages_enabled();

    return page_kasan_tag(page) == KASAN_TAG_KERNEL;
}

static void kernel_init_pages(struct page *page, int numpages)
{
    int i;

    /* s390's use of memset() could override KASAN redzones. */
    kasan_disable_current();
    for (i = 0; i < numpages; i++)
        clear_highpage_kasan_tagged(page + i);
    kasan_enable_current();
}

static void bad_page(struct page *page, const char *reason)
{
    static unsigned long resume;
    static unsigned long nr_shown;
    static unsigned long nr_unshown;

    /*
     * Allow a burst of 60 reports, then keep quiet for that minute;
     * or allow a steady drip of one report per second.
     */
    if (nr_shown == 60) {
        if (time_before(jiffies, resume)) {
            nr_unshown++;
            goto out;
        }
        if (nr_unshown) {
            pr_alert(
                  "BUG: Bad page state: %lu messages suppressed\n",
                nr_unshown);
            nr_unshown = 0;
        }
        nr_shown = 0;
    }
    if (nr_shown++ == 0)
        resume = jiffies + 60 * HZ;

    pr_alert("BUG: Bad page state in process %s  pfn:%05lx\n",
        current->comm, page_to_pfn(page));
    dump_page(page, reason);

    print_modules();
    dump_stack();
out:
    /* Leave bad fields for debug, except PageBuddy could make trouble */
    if (PageBuddy(page))
        __ClearPageBuddy(page);
    add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

static int free_tail_page_prepare(struct page *head_page, struct page *page)
{
    struct folio *folio = (struct folio *)head_page;
    int ret = 1;

    /*
     * We rely page->lru.next never has bit 0 set, unless the page
     * is PageTail(). Let's make sure that's true even for poisoned ->lru.
     */
    BUILD_BUG_ON((unsigned long)LIST_POISON1 & 1);

    if (!is_check_pages_enabled()) {
        ret = 0;
        goto out;
    }
    switch (page - head_page) {
    case 1:
        /* the first tail page: these may be in place of ->mapping */
        if (unlikely(folio_entire_mapcount(folio))) {
            bad_page(page, "nonzero entire_mapcount");
            goto out;
        }
        if (unlikely(folio_large_mapcount(folio))) {
            bad_page(page, "nonzero large_mapcount");
            goto out;
        }
        if (unlikely(atomic_read(&folio->_nr_pages_mapped))) {
            bad_page(page, "nonzero nr_pages_mapped");
            goto out;
        }
        if (unlikely(atomic_read(&folio->_pincount))) {
            bad_page(page, "nonzero pincount");
            goto out;
        }
        break;
    case 2:
        /* the second tail page: deferred_list overlaps ->mapping */
        if (unlikely(!list_empty(&folio->_deferred_list))) {
            bad_page(page, "on deferred list");
            goto out;
        }
        break;
    default:
        if (page->mapping != TAIL_MAPPING) {
            bad_page(page, "corrupted mapping in tail page");
            goto out;
        }
        break;
    }
        if (unlikely(!PageTail(page))) {
        bad_page(page, "PageTail not set");
        goto out;
    }
    if (unlikely(compound_head(page) != head_page)) {
        bad_page(page, "compound_head not consistent");
        goto out;
    }
    ret = 0;
out:
    page->mapping = NULL;
    clear_compound_head(page);
    return ret;
}

/*
 * A bad page could be due to a number of fields. Instead of multiple branches,
 * try and check multiple fields with one check. The caller must do a detailed
 * check if necessary.
 */
static inline bool page_expected_state(struct page *page,
                    unsigned long check_flags)
{
    if (unlikely(atomic_read(&page->_mapcount) != -1))
        return false;

    if (unlikely((unsigned long)page->mapping |
            page_ref_count(page) |
#ifdef CONFIG_MEMCG
            page->memcg_data |
#endif
            page_pool_page_is_pp(page) |
            (page->flags & check_flags)))
        return false;

    return true;
}

static const char *page_bad_reason(struct page *page, unsigned long flags)
{
    const char *bad_reason = NULL;

    if (unlikely(atomic_read(&page->_mapcount) != -1))
        bad_reason = "nonzero mapcount";
    if (unlikely(page->mapping != NULL))
        bad_reason = "non-NULL mapping";
    if (unlikely(page_ref_count(page) != 0))
        bad_reason = "nonzero _refcount";
    if (unlikely(page->flags & flags)) {
        if (flags == PAGE_FLAGS_CHECK_AT_PREP)
            bad_reason = "PAGE_FLAGS_CHECK_AT_PREP flag(s) set";
        else
            bad_reason = "PAGE_FLAGS_CHECK_AT_FREE flag(s) set";
    }
#ifdef CONFIG_MEMCG
    if (unlikely(page->memcg_data))
        bad_reason = "page still charged to cgroup";
#endif
    if (unlikely(page_pool_page_is_pp(page)))
        bad_reason = "page_pool leak";
    return bad_reason;
}

static void free_page_is_bad_report(struct page *page)
{
    bad_page(page,
         page_bad_reason(page, PAGE_FLAGS_CHECK_AT_FREE));
}

static inline bool free_page_is_bad(struct page *page)
{
    if (likely(page_expected_state(page, PAGE_FLAGS_CHECK_AT_FREE)))
        return false;

    /* Something has gone sideways, find it */
    free_page_is_bad_report(page);
    return true;
}

__always_inline bool free_pages_prepare(struct page *page,
            unsigned int order)
{
    int bad = 0;
    bool skip_kasan_poison = should_skip_kasan_poison(page);
    bool init = want_init_on_free();
    bool compound = PageCompound(page);
    struct folio *folio = page_folio(page);

    VM_BUG_ON_PAGE(PageTail(page), page);

    trace_mm_page_free(page, order);
    kmsan_free_page(page, order);

    if (memcg_kmem_online() && PageMemcgKmem(page))
        __memcg_kmem_uncharge_page(page, order);

    /*
     * In rare cases, when truncation or holepunching raced with
     * munlock after VM_LOCKED was cleared, Mlocked may still be
     * found set here.  This does not indicate a problem, unless
     * "unevictable_pgs_cleared" appears worryingly large.
     */
    if (unlikely(folio_test_mlocked(folio))) {
        long nr_pages = folio_nr_pages(folio);

        __folio_clear_mlocked(folio);
        zone_stat_mod_folio(folio, NR_MLOCK, -nr_pages);
        count_vm_events(UNEVICTABLE_PGCLEARED, nr_pages);
    }

    if (unlikely(PageHWPoison(page)) && !order) {
        /* Do not let hwpoison pages hit pcplists/buddy */
        reset_page_owner(page, order);
        page_table_check_free(page, order);
        pgalloc_tag_sub(page, 1 << order);

        /*
         * The page is isolated and accounted for.
         * Mark the codetag as empty to avoid accounting error
         * when the page is freed by unpoison_memory().
         */
        clear_page_tag_ref(page);
        return false;
    }

    VM_BUG_ON_PAGE(compound && compound_order(page) != order, page);

    /*
     * Check tail pages before head page information is cleared to
     * avoid checking PageCompound for order-0 pages.
     */
    if (unlikely(order)) {
        int i;

        if (compound)
            page[1].flags &= ~PAGE_FLAGS_SECOND;
        for (i = 1; i < (1 << order); i++) {
            if (compound)
                bad += free_tail_page_prepare(page, page + i);
            if (is_check_pages_enabled()) {
                if (free_page_is_bad(page + i)) {
                    bad++;
                    continue;
                }
            }
            (page + i)->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
        }
    }
    if (PageMappingFlags(page)) {
        if (PageAnon(page))
            mod_mthp_stat(order, MTHP_STAT_NR_ANON, -1);
        page->mapping = NULL;
    }
    if (is_check_pages_enabled()) {
        if (free_page_is_bad(page))
            bad++;
        if (bad)
            return false;
    }

    page_cpupid_reset_last(page);
    page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
    reset_page_owner(page, order);
    page_table_check_free(page, order);
    pgalloc_tag_sub(page, 1 << order);

    if (!PageHighMem(page)) {
        debug_check_no_locks_freed(page_address(page),
                       PAGE_SIZE << order);
        debug_check_no_obj_freed(page_address(page),
                       PAGE_SIZE << order);
    }

    kernel_poison_pages(page, 1 << order);

    /*
     * As memory initialization might be integrated into KASAN,
     * KASAN poisoning and memory initialization code must be
     * kept together to avoid discrepancies in behavior.
     *
     * With hardware tag-based KASAN, memory tags must be set before the
     * page becomes unavailable via debug_pagealloc or arch_free_page.
     */
    if (!skip_kasan_poison) {
        kasan_poison_pages(page, order, init);

        /* Memory is already initialized if KASAN did it internally. */
        if (kasan_has_integrated_init())
            init = false;
    }
    if (init)
        kernel_init_pages(page, 1 << order);

    /*
     * arch_free_page() can make the page's contents inaccessible.  s390
     * does this.  So nothing which can access the page's contents should
     * happen after this.
     */
    arch_free_page(page, order);

    debug_pagealloc_unmap_pages(page, 1 << order);

    return true;
}

/* Return a pointer to the bitmap storing bits affecting a block of pages */
static inline unsigned long *get_pageblock_bitmap(const struct page *page,
                            unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
    return section_to_usemap(__pfn_to_section(pfn));
#else
    return page_zone(page)->pageblock_flags;
#endif /* CONFIG_SPARSEMEM */
}

static inline int pfn_to_bitidx(const struct page *page, unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
    pfn &= (PAGES_PER_SECTION-1);
#else
    pfn = pfn - pageblock_start_pfn(page_zone(page)->zone_start_pfn);
#endif /* CONFIG_SPARSEMEM */
    return (pfn >> pageblock_order) * NR_PAGEBLOCK_BITS;
}

/**
 * get_pfnblock_flags_mask - Return the requested group of flags for the pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 * @mask: mask of bits that the caller is interested in
 *
 * Return: pageblock_bits flags
 */
unsigned long get_pfnblock_flags_mask(const struct page *page,
                    unsigned long pfn, unsigned long mask)
{
    unsigned long *bitmap;
    unsigned long bitidx, word_bitidx;
    unsigned long word;

    bitmap = get_pageblock_bitmap(page, pfn);
    bitidx = pfn_to_bitidx(page, pfn);
    word_bitidx = bitidx / BITS_PER_LONG;
    bitidx &= (BITS_PER_LONG-1);
    /*
     * This races, without locks, with set_pfnblock_flags_mask(). Ensure
     * a consistent read of the memory array, so that results, even though
     * racy, are not corrupted.
     */
    word = READ_ONCE(bitmap[word_bitidx]);
    return (word >> bitidx) & mask;
}

/*
 * Higher-order pages are called "compound pages".  They are structured thusly:
 *
 * The first PAGE_SIZE page is called the "head page" and have PG_head set.
 *
 * The remaining PAGE_SIZE pages are called "tail pages". PageTail() is encoded
 * in bit 0 of page->compound_head. The rest of bits is pointer to head page.
 *
 * The first tail page's ->compound_order holds the order of allocation.
 * This usage means that zero-order pages may not be compound.
 */

void prep_compound_page(struct page *page, unsigned int order)
{
    int i;
    int nr_pages = 1 << order;

    __SetPageHead(page);
    for (i = 1; i < nr_pages; i++)
        prep_compound_tail(page, i);

    prep_compound_head(page, order);
}

bool zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
              int highest_zoneidx, unsigned int alloc_flags)
{
    return __zone_watermark_ok(z, order, mark, highest_zoneidx, alloc_flags,
                    zone_page_state(z, NR_FREE_PAGES));
}

/*
 * Return true if free base pages are above 'mark'. For high-order checks it
 * will return true of the order-0 watermark is reached and there is at least
 * one free page of a suitable size. Checking now avoids taking the zone lock
 * to check in the allocation paths if no pages are free.
 */
bool __zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
             int highest_zoneidx, unsigned int alloc_flags,
             long free_pages)
{
    pr_notice("%s: No impl.", __func__);
    return false;
}
