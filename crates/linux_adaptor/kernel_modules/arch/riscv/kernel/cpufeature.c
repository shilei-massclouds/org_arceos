// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copied from arch/arm64/kernel/cpufeature.c
 *
 * Copyright (C) 2015 ARM Ltd.
 * Copyright (C) 2017 SiFive
 */

#include <linux/acpi.h>
#include <linux/bitmap.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/ctype.h>
#include <linux/log2.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/of.h>
#include <asm/acpi.h>
#include <asm/alternative.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/hwcap.h>
#include <asm/patch.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/vector.h>
#include <asm/vendor_extensions.h>

#define NUM_ALPHA_EXTS ('z' - 'a' + 1)

#ifdef CONFIG_RISCV_ISA_FALLBACK
bool __initdata riscv_isa_fallback = true;
#else
#error "Undefined [CONFIG_RISCV_ISA_FALLBACK]!"
#endif
