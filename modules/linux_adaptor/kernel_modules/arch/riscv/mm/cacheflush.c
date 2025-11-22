// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 SiFive
 */

#include <linux/acpi.h>
#include <linux/of.h>
#include <linux/prctl.h>
#include <asm/acpi.h>
#include <asm/cacheflush.h>

unsigned int riscv_cbom_block_size;
EXPORT_SYMBOL_GPL(riscv_cbom_block_size);

unsigned int riscv_cboz_block_size;
EXPORT_SYMBOL_GPL(riscv_cboz_block_size);
