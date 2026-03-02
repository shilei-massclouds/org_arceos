// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/interval_tree.c - interval tree for mapping->i_mmap
 *
 * Copyright (C) 2012, Michel Lespinasse <walken@google.com>
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/rmap.h>
#include <linux/interval_tree_generic.h>

static inline unsigned long vma_start_pgoff(struct vm_area_struct *v)
{
    return v->vm_pgoff;
}

static inline unsigned long vma_last_pgoff(struct vm_area_struct *v)
{
    return v->vm_pgoff + vma_pages(v) - 1;
}

INTERVAL_TREE_DEFINE(struct vm_area_struct, shared.rb,
             unsigned long, shared.rb_subtree_last,
             vma_start_pgoff, vma_last_pgoff, /* empty */, vma_interval_tree)

