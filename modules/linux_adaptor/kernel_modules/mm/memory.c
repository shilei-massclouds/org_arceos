#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/memremap.h>
#include <linux/kmsan.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
#include <linux/delayacct.h>
#include <linux/init.h>
#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
#include <linux/memory-tiers.h>
#include <linux/debugfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>
#include <linux/oom.h>
#include <linux/numa.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/vmalloc.h>
#include <linux/sched/sysctl.h>

#include <trace/events/kmem.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

#include "pgalloc-track.h"
#include "internal.h"
#include "swap.h"

#if defined(CONFIG_PROVE_LOCKING) || defined(CONFIG_DEBUG_ATOMIC_SLEEP)
void __might_fault(const char *file, int line)
{
    if (pagefault_disabled())
        return;
    __might_sleep(file, line);
    if (current->mm)
        might_lock_read(&current->mm->mmap_lock);
}
EXPORT_SYMBOL(__might_fault);
#endif

static inline void unmap_mapping_range_tree(struct rb_root_cached *root,
                        pgoff_t first_index,
                        pgoff_t last_index,
                        struct zap_details *details)
{
#if 0
    struct vm_area_struct *vma;
    pgoff_t vba, vea, zba, zea;

    vma_interval_tree_foreach(vma, root, first_index, last_index) {
        vba = vma->vm_pgoff;
        vea = vba + vma_pages(vma) - 1;
        zba = max(first_index, vba);
        zea = min(last_index, vea);

        unmap_mapping_range_vma(vma,
            ((zba - vba) << PAGE_SHIFT) + vma->vm_start,
            ((zea - vba + 1) << PAGE_SHIFT) + vma->vm_start,
                details);
    }
#endif
    pr_notice("%s: No impl.", __func__);
}

/**
 * unmap_mapping_range - unmap the portion of all mmaps in the specified
 * address_space corresponding to the specified byte range in the underlying
 * file.
 *
 * @mapping: the address space containing mmaps to be unmapped.
 * @holebegin: byte in first page to unmap, relative to the start of
 * the underlying file.  This will be rounded down to a PAGE_SIZE
 * boundary.  Note that this is different from truncate_pagecache(), which
 * must keep the partial page.  In contrast, we must get rid of
 * partial pages.
 * @holelen: size of prospective hole in bytes.  This will be rounded
 * up to a PAGE_SIZE boundary.  A holelen of zero truncates to the
 * end of the file.
 * @even_cows: 1 when truncating a file, unmap even private COWed pages;
 * but 0 when invalidating pagecache, don't throw away private data.
 */
void unmap_mapping_range(struct address_space *mapping,
        loff_t const holebegin, loff_t const holelen, int even_cows)
{
    pgoff_t hba = (pgoff_t)(holebegin) >> PAGE_SHIFT;
    pgoff_t hlen = ((pgoff_t)(holelen) + PAGE_SIZE - 1) >> PAGE_SHIFT;

    /* Check for overflow. */
    if (sizeof(holelen) > sizeof(hlen)) {
        long long holeend =
            (holebegin + holelen + PAGE_SIZE - 1) >> PAGE_SHIFT;
        if (holeend & ~(long long)ULONG_MAX)
            hlen = ULONG_MAX - hba + 1;
    }

    unmap_mapping_pages(mapping, hba, hlen, even_cows);
}

/**
 * unmap_mapping_pages() - Unmap pages from processes.
 * @mapping: The address space containing pages to be unmapped.
 * @start: Index of first page to be unmapped.
 * @nr: Number of pages to be unmapped.  0 to unmap to end of file.
 * @even_cows: Whether to unmap even private COWed pages.
 *
 * Unmap the pages in this address space from any userspace process which
 * has them mmaped.  Generally, you want to remove COWed pages as well when
 * a file is being truncated, but not when invalidating pages from the page
 * cache.
 */
void unmap_mapping_pages(struct address_space *mapping, pgoff_t start,
        pgoff_t nr, bool even_cows)
{
    struct zap_details details = { };
    pgoff_t first_index = start;
    pgoff_t last_index = start + nr - 1;

    details.even_cows = even_cows;
    if (last_index < first_index)
        last_index = ULONG_MAX;

    i_mmap_lock_read(mapping);
    if (unlikely(!RB_EMPTY_ROOT(&mapping->i_mmap.rb_root)))
        unmap_mapping_range_tree(&mapping->i_mmap, first_index,
                     last_index, &details);
    i_mmap_unlock_read(mapping);
}
