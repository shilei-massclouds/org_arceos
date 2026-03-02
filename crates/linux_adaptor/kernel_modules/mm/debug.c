// SPDX-License-Identifier: GPL-2.0
/*
 * mm/debug.c
 *
 * mm/ specific debug routines.
 *
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/trace_events.h>
#include <linux/memcontrol.h>
#include <trace/events/mmflags.h>
#include <linux/migrate.h>
#include <linux/page_owner.h>
#include <linux/ctype.h>

#include "internal.h"
#include <trace/events/migrate.h>

#include "adaptor.h"

static bool page_init_poisoning __read_mostly = true;

const char *migrate_reason_names[MR_TYPES] = {
    MIGRATE_REASON
};

const struct trace_print_flags pageflag_names[] = {
    __def_pageflag_names,
    {0, NULL}
};

const struct trace_print_flags gfpflag_names[] = {
    __def_gfpflag_names,
    {0, NULL}
};

const struct trace_print_flags vmaflag_names[] = {
    __def_vmaflag_names,
    {0, NULL}
};

#define DEF_PAGETYPE_NAME(_name) [PGTY_##_name - 0xf0] =  __stringify(_name)

static const char *page_type_names[] = {
    DEF_PAGETYPE_NAME(slab),
    DEF_PAGETYPE_NAME(hugetlb),
    DEF_PAGETYPE_NAME(offline),
    DEF_PAGETYPE_NAME(guard),
    DEF_PAGETYPE_NAME(table),
    DEF_PAGETYPE_NAME(buddy),
    DEF_PAGETYPE_NAME(unaccepted),
};

void dump_page(const struct page *page, const char *reason)
{
    pr_err("%s: Page(0x%lx): pfn(0x%lx) reason: %s",
           __func__, page, page_to_pfn(page), reason);
}

void page_init_poison(struct page *page, size_t size)
{
    if (page_init_poisoning)
        memset(page, PAGE_POISON_PATTERN, size);
}

void dump_vma(const struct vm_area_struct *vma)
{
    pr_emerg("vma %px start %px end %px mm %px\n"
        "prot %lx anon_vma %px vm_ops %px\n"
        "pgoff %lx file %px private_data %px\n"
        "flags: %#lx(%pGv)\n",
        vma, (void *)vma->vm_start, (void *)vma->vm_end, vma->vm_mm,
        (unsigned long)pgprot_val(vma->vm_page_prot),
        vma->anon_vma, vma->vm_ops, vma->vm_pgoff,
        vma->vm_file, vma->vm_private_data,
        vma->vm_flags, &vma->vm_flags);
}
