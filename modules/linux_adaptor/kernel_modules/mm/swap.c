#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/mm_inline.h>
#include <linux/percpu_counter.h>
#include <linux/memremap.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/backing-dev.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/uio.h>
#include <linux/hugetlb.h>
#include <linux/page_idle.h>
#include <linux/local_lock.h>
#include <linux/buffer_head.h>

#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/pagemap.h>

#include "../adaptor.h"

typedef void (*move_fn_t)(struct lruvec *lruvec, struct folio *folio);

struct cpu_fbatches {
    /*
     * The following folio batches are grouped together because they are protected
     * by disabling preemption (and interrupts remain enabled).
     */
    local_lock_t lock;
    struct folio_batch lru_add;
    struct folio_batch lru_deactivate_file;
    struct folio_batch lru_deactivate;
    struct folio_batch lru_lazyfree;
#ifdef CONFIG_SMP
    struct folio_batch lru_activate;
#endif
    /* Protecting the following batches which require disabling interrupts */
    local_lock_t lock_irq;
    struct folio_batch lru_move_tail;
};

static DEFINE_PER_CPU(struct cpu_fbatches, cpu_fbatches) = {
    .lock = INIT_LOCAL_LOCK(lock),
    .lock_irq = INIT_LOCAL_LOCK(lock_irq),
};

atomic_t lru_disable_count = ATOMIC_INIT(0);

static void lru_add(struct lruvec *lruvec, struct folio *folio)
{
    PANIC("");
}

static void folio_batch_move_lru(struct folio_batch *fbatch, move_fn_t move_fn)
{
    int i;
    struct lruvec *lruvec = NULL;
    unsigned long flags = 0;

#if 0
    for (i = 0; i < folio_batch_count(fbatch); i++) {
        struct folio *folio = fbatch->folios[i];

        folio_lruvec_relock_irqsave(folio, &lruvec, &flags);
        move_fn(lruvec, folio);

        folio_set_lru(folio);
    }

    if (lruvec)
        unlock_page_lruvec_irqrestore(lruvec, flags);
    folios_put(fbatch);
#endif
    PANIC("");
}

static void __folio_batch_add_and_move(struct folio_batch __percpu *fbatch,
        struct folio *folio, move_fn_t move_fn,
        bool on_lru, bool disable_irq)
{
    unsigned long flags;

    if (on_lru && !folio_test_clear_lru(folio))
        return;

    folio_get(folio);

    if (disable_irq)
        local_lock_irqsave(&cpu_fbatches.lock_irq, flags);
    else
        local_lock(&cpu_fbatches.lock);

    if (!folio_batch_add(this_cpu_ptr(fbatch), folio) || folio_test_large(folio) ||
        lru_cache_disabled())
        folio_batch_move_lru(this_cpu_ptr(fbatch), move_fn);

    if (disable_irq)
        local_unlock_irqrestore(&cpu_fbatches.lock_irq, flags);
    else
        local_unlock(&cpu_fbatches.lock);
}

#define folio_batch_add_and_move(folio, op, on_lru)                     \
    __folio_batch_add_and_move(                             \
        &cpu_fbatches.op,                               \
        folio,                                      \
        op,                                     \
        on_lru,                                     \
        offsetof(struct cpu_fbatches, op) >= offsetof(struct cpu_fbatches, lock_irq)    \
    )

/**
 * folio_mark_accessed - Mark a folio as having seen activity.
 * @folio: The folio to mark.
 *
 * This function will perform one of the following transitions:
 *
 * * inactive,unreferenced  ->  inactive,referenced
 * * inactive,referenced    ->  active,unreferenced
 * * active,unreferenced    ->  active,referenced
 *
 * When a newly allocated folio is not yet visible, so safe for non-atomic ops,
 * __folio_set_referenced() may be substituted for folio_mark_accessed().
 */
void folio_mark_accessed(struct folio *folio)
{
    pr_err("%s: No impl.", __func__);
}

/**
 * folio_add_lru - Add a folio to an LRU list.
 * @folio: The folio to be added to the LRU.
 *
 * Queue the folio for addition to the LRU. The decision on whether
 * to add the page to the [in]active [file|anon] list is deferred until the
 * folio_batch is drained. This gives a chance for the caller of folio_add_lru()
 * have the folio added to the active list using folio_mark_accessed().
 */
void folio_add_lru(struct folio *folio)
{
    VM_BUG_ON_FOLIO(folio_test_active(folio) &&
            folio_test_unevictable(folio), folio);
    VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);

    /* see the comment in lru_gen_add_folio() */
    if (lru_gen_enabled() && !folio_test_unevictable(folio) &&
        lru_gen_in_fault() && !(current->flags & PF_MEMALLOC))
        folio_set_active(folio);

    folio_batch_add_and_move(folio, lru_add, false);
}

/*
 * The folios which we're about to release may be in the deferred lru-addition
 * queues.  That would prevent them from really being freed right now.  That's
 * OK from a correctness point of view but is inefficient - those folios may be
 * cache-warm and we want to give them back to the page allocator ASAP.
 *
 * So __folio_batch_release() will drain those queues here.
 * folio_batch_move_lru() calls folios_put() directly to avoid
 * mutual recursion.
 */
void __folio_batch_release(struct folio_batch *fbatch)
{
    if (!fbatch->percpu_pvec_drained) {
        lru_add_drain();
        fbatch->percpu_pvec_drained = true;
    }
    folios_put(fbatch);
}

static void __page_cache_release(struct folio *folio, struct lruvec **lruvecp,
        unsigned long *flagsp)
{
    if (folio_test_lru(folio)) {
#if 0
        folio_lruvec_relock_irqsave(folio, lruvecp, flagsp);
        lruvec_del_folio(*lruvecp, folio);
        __folio_clear_lru_flags(folio);
#endif
        PANIC("");
    }
}

/**
 * folios_put_refs - Reduce the reference count on a batch of folios.
 * @folios: The folios.
 * @refs: The number of refs to subtract from each folio.
 *
 * Like folio_put(), but for a batch of folios.  This is more efficient
 * than writing the loop yourself as it will optimise the locks which need
 * to be taken if the folios are freed.  The folios batch is returned
 * empty and ready to be reused for another batch; there is no need
 * to reinitialise it.  If @refs is NULL, we subtract one from each
 * folio refcount.
 *
 * Context: May be called in process or interrupt context, but not in NMI
 * context.  May be called while holding a spinlock.
 */
void folios_put_refs(struct folio_batch *folios, unsigned int *refs)
{
    int i, j;
    struct lruvec *lruvec = NULL;
    unsigned long flags = 0;

    for (i = 0, j = 0; i < folios->nr; i++) {
        struct folio *folio = folios->folios[i];
        unsigned int nr_refs = refs ? refs[i] : 1;

        if (is_huge_zero_folio(folio))
            continue;

        if (folio_is_zone_device(folio)) {
            if (lruvec) {
                unlock_page_lruvec_irqrestore(lruvec, flags);
                lruvec = NULL;
            }
            if (put_devmap_managed_folio_refs(folio, nr_refs))
                continue;
            if (folio_ref_sub_and_test(folio, nr_refs))
                free_zone_device_folio(folio);
            continue;
        }

        if (!folio_ref_sub_and_test(folio, nr_refs))
            continue;

        /* hugetlb has its own memcg */
        if (folio_test_hugetlb(folio)) {
            if (lruvec) {
                unlock_page_lruvec_irqrestore(lruvec, flags);
                lruvec = NULL;
            }
            free_huge_folio(folio);
            continue;
        }
        folio_unqueue_deferred_split(folio);
        __page_cache_release(folio, &lruvec, &flags);

        if (j != i)
            folios->folios[j] = folio;
        j++;
    }
    if (lruvec)
        unlock_page_lruvec_irqrestore(lruvec, flags);
    if (!j) {
        folio_batch_reinit(folios);
        return;
    }

    folios->nr = j;
    //mem_cgroup_uncharge_folios(folios);
    free_unref_folios(folios);

    PANIC("");
}

void lru_add_drain(void)
{
    local_lock(&cpu_fbatches.lock);
    lru_add_drain_cpu(smp_processor_id());
    local_unlock(&cpu_fbatches.lock);
    mlock_drain_local();
}

/*
 * Drain pages out of the cpu's folio_batch.
 * Either "cpu" is the current CPU, and preemption has already been
 * disabled; or "cpu" is being hot-unplugged, and is already dead.
 */
void lru_add_drain_cpu(int cpu)
{
    pr_err("%s: No impl.", __func__);
}

void lru_add_drain_all(void)
{
    pr_err("%s: No impl.", __func__);
}

/*
 * If the folio cannot be invalidated, it is moved to the
 * inactive list to speed up its reclaim.  It is moved to the
 * head of the list, rather than the tail, to give the flusher
 * threads some time to write it out, as this is much more
 * effective than the single-page writeout from reclaim.
 *
 * If the folio isn't mapped and dirty/writeback, the folio
 * could be reclaimed asap using the reclaim flag.
 *
 * 1. active, mapped folio -> none
 * 2. active, dirty/writeback folio -> inactive, head, reclaim
 * 3. inactive, mapped folio -> none
 * 4. inactive, dirty/writeback folio -> inactive, head, reclaim
 * 5. inactive, clean -> inactive, tail
 * 6. Others -> none
 *
 * In 4, it moves to the head of the inactive list so the folio is
 * written out by flusher threads as this is much more efficient
 * than the single-page writeout from reclaim.
 */
static void lru_deactivate_file(struct lruvec *lruvec, struct folio *folio)
{
    PANIC("");
}

/**
 * folio_batch_remove_exceptionals() - Prune non-folios from a batch.
 * @fbatch: The batch to prune
 *
 * find_get_entries() fills a batch with both folios and shadow/swap/DAX
 * entries.  This function prunes all the non-folio entries from @fbatch
 * without leaving holes, so that it can be passed on to folio-only batch
 * operations.
 */
void folio_batch_remove_exceptionals(struct folio_batch *fbatch)
{
    unsigned int i, j;

    for (i = 0, j = 0; i < folio_batch_count(fbatch); i++) {
        struct folio *folio = fbatch->folios[i];
        if (!xa_is_value(folio))
            fbatch->folios[j++] = folio;
    }
    fbatch->nr = j;
}

/**
 * deactivate_file_folio() - Deactivate a file folio.
 * @folio: Folio to deactivate.
 *
 * This function hints to the VM that @folio is a good reclaim candidate,
 * for example if its invalidation fails due to the folio being dirty
 * or under writeback.
 *
 * Context: Caller holds a reference on the folio.
 */
void deactivate_file_folio(struct folio *folio)
{
    /* Deactivating an unevictable folio will not accelerate reclaim */
    if (folio_test_unevictable(folio))
        return;

    folio_batch_add_and_move(folio, lru_deactivate_file, true);
}
