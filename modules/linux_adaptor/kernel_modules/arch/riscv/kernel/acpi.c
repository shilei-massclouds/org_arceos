// SPDX-License-Identifier: GPL-2.0-only
/*
 *  RISC-V Specific Low-Level ACPI Boot Support
 *
 *  Copyright (C) 2013-2014, Linaro Ltd.
 *  Author: Al Stone <al.stone@linaro.org>
 *  Author: Graeme Gregory <graeme.gregory@linaro.org>
 *  Author: Hanjun Guo <hanjun.guo@linaro.org>
 *  Author: Tomasz Nowicki <tomasz.nowicki@linaro.org>
 *  Author: Naresh Bhat <naresh.bhat@linaro.org>
 *
 *  Copyright (C) 2021-2023, Ventana Micro Systems Inc.
 *  Author: Sunil V L <sunilvl@ventanamicro.com>
 */

#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/io.h>
#include <linux/memblock.h>
#include <linux/of_fdt.h>
#include <linux/pci.h>
#include <linux/serial_core.h>


int acpi_pci_disabled = 1;  /* skip ACPI PCI scan and IRQ initialization */
