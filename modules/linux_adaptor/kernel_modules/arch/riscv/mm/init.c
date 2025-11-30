// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 * Copyright (C) 2020 FORTH-ICS/CARV
 *  Nick Kossifidis <mick@ics.forth.gr>
 */

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/initrd.h>
#include <linux/swap.h>
#include <linux/swiotlb.h>
#include <linux/sizes.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/libfdt.h>
#include <linux/set_memory.h>
#include <linux/dma-map-ops.h>
#include <linux/crash_dump.h>
#include <linux/hugetlb.h>
#ifdef CONFIG_RELOCATABLE
#include <linux/elf.h>
#endif
#include <linux/kfence.h>
#include <linux/execmem.h>

#include <asm/fixmap.h>
#include <asm/io.h>
#include <asm/kasan.h>
#include <asm/numa.h>
#include <asm/pgtable.h>
#include <asm/sections.h>
#include <asm/soc.h>
#include <asm/sparsemem.h>
#include <asm/tlbflush.h>

//#include "../kernel/head.h"

void *_dtb_early_va __initdata;
//uintptr_t _dtb_early_pa __initdata;

