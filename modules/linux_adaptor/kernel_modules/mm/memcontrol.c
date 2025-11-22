// SPDX-License-Identifier: GPL-2.0-or-later
/* memcontrol.c - Memory Controller
 *
 * Copyright IBM Corporation, 2007
 * Author Balbir Singh <balbir@linux.vnet.ibm.com>
 *
 * Copyright 2007 OpenVZ SWsoft Inc
 * Author: Pavel Emelianov <xemul@openvz.org>
 *
 * Memory thresholds
 * Copyright (C) 2009 Nokia Corporation
 * Author: Kirill A. Shutemov
 *
 * Kernel Memory Controller
 * Copyright (C) 2012 Parallels Inc. and Google Inc.
 * Authors: Glauber Costa and Suleiman Souhlal
 *
 * Native page reclaim
 * Charge lifetime sanitation
 * Lockless page tracking & accounting
 * Unified hierarchy configuration model
 * Copyright (C) 2015 Red Hat, Inc., Johannes Weiner
 *
 * Per memcg lru locking
 * Copyright (C) 2020 Alibaba, Inc, Alex Shi
 */
#include <linux/cgroup-defs.h>
#include <linux/page_counter.h>
#include <linux/memcontrol.h>
#include <linux/cgroup.h>
#include <linux/sched/mm.h>
#include <linux/shmem_fs.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/vm_event_item.h>
#include <linux/smp.h>
#include <linux/page-flags.h>
#include <linux/backing-dev.h>
#include <linux/bit_spinlock.h>
#include <linux/rcupdate.h>
#include <linux/limits.h>
#include <linux/export.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/swapops.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/parser.h>
#include <linux/vmpressure.h>
#include <linux/memremap.h>
#include <linux/mm_inline.h>
#include <linux/swap_cgroup.h>
#include <linux/cpu.h>
#include <linux/oom.h>
#include <linux/lockdep.h>
#include <linux/resume_user_mode.h>
#include <linux/psi.h>
#include <linux/seq_buf.h>
#include <linux/sched/isolation.h>
#include <linux/kmemleak.h>
#include "internal.h"
#include <net/sock.h>
#include <net/ip.h>
#include "slab.h"
#include "memcontrol-v1.h"

#include <linux/uaccess.h>

#include <trace/events/vmscan.h>

#include "adaptor.h"

/*
 * A lot of the calls to the cache allocation functions are expected to be
 * inlined by the compiler. Since the calls to memcg_slab_post_alloc_hook() are
 * conditional to this static branch, we'll have to allow modules that does
 * kmem_cache_alloc and the such to see this symbol as well
 */
DEFINE_STATIC_KEY_FALSE(memcg_kmem_online_key);
EXPORT_SYMBOL(memcg_kmem_online_key);

struct mem_cgroup *root_mem_cgroup __read_mostly;

/**
 * folio_lruvec_lock_irqsave - Lock the lruvec for a folio.
 * @folio: Pointer to the folio.
 * @flags: Pointer to irqsave flags.
 *
 * These functions are safe to use under any of the following conditions:
 * - folio locked
 * - folio_test_lru false
 * - folio_memcg_lock()
 * - folio frozen (refcount of 0)
 *
 * Return: The lruvec this folio is on with its lock held and interrupts
 * disabled.
 */
struct lruvec *folio_lruvec_lock_irqsave(struct folio *folio,
        unsigned long *flags)
{
    struct lruvec *lruvec = folio_lruvec(folio);

    spin_lock_irqsave(&lruvec->lru_lock, *flags);
    lruvec_memcg_debug(lruvec, folio);

    return lruvec;
}

#ifdef CONFIG_DEBUG_VM
void lruvec_memcg_debug(struct lruvec *lruvec, struct folio *folio)
{
    struct mem_cgroup *memcg;

    if (mem_cgroup_disabled())
        return;

    memcg = folio_memcg(folio);

    if (!memcg)
        VM_BUG_ON_FOLIO(!mem_cgroup_is_root(lruvec_memcg(lruvec)), folio);
    else
        VM_BUG_ON_FOLIO(lruvec_memcg(lruvec) != memcg, folio);
}
#endif

/**
 * __mod_lruvec_state - update lruvec memory statistics
 * @lruvec: the lruvec
 * @idx: the stat item
 * @val: delta to add to the counter, can be negative
 *
 * The lruvec is the intersection of the NUMA node and a cgroup. This
 * function updates the all three counters that are affected by a
 * change of state at this level: per-node, per-cgroup, per-lruvec.
 */
void __mod_lruvec_state(struct lruvec *lruvec, enum node_stat_item idx,
            int val)
{
#if 0
    /* Update node */
    __mod_node_page_state(lruvec_pgdat(lruvec), idx, val);

    /* Update memcg and lruvec */
    if (!mem_cgroup_disabled())
        __mod_memcg_lruvec_state(lruvec, idx, val);
#endif
    PANIC("");
}

/**
 * mem_cgroup_update_lru_size - account for adding or removing an lru page
 * @lruvec: mem_cgroup per zone lru vector
 * @lru: index of lru list the page is sitting on
 * @zid: zone id of the accounted pages
 * @nr_pages: positive when adding or negative when removing
 *
 * This function must be called under lru_lock, just before a page is added
 * to or just after a page is removed from an lru list.
 */
void mem_cgroup_update_lru_size(struct lruvec *lruvec, enum lru_list lru,
                int zid, int nr_pages)
{
    struct mem_cgroup_per_node *mz;
    unsigned long *lru_size;
    long size;

    if (mem_cgroup_disabled())
        return;

    mz = container_of(lruvec, struct mem_cgroup_per_node, lruvec);
    lru_size = &mz->lru_zone_size[zid][lru];

    if (nr_pages < 0)
        *lru_size += nr_pages;

    size = *lru_size;
    if (WARN_ONCE(size < 0,
        "%s(%p, %d, %d): lru_size %ld\n",
        __func__, lruvec, lru, nr_pages, size)) {
        VM_BUG_ON(1);
        *lru_size = 0;
    }

    if (nr_pages > 0)
        *lru_size += nr_pages;
}
