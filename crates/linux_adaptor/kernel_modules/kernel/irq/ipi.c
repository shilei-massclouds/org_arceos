// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015 Imagination Technologies Ltd
 * Author: Qais Yousef <qais.yousef@imgtec.com>
 *
 * This file contains driver APIs to the IPI subsystem.
 */

#define pr_fmt(fmt) "genirq/ipi: " fmt

#include <linux/irqdomain.h>
#include <linux/irq.h>

#include "adaptor.h"

/**
 * __ipi_send_mask - send an IPI to target Linux SMP CPU(s)
 * @desc:   pointer to irq_desc of the IRQ
 * @dest:   dest CPU(s), must be a subset of the mask passed to
 *      irq_reserve_ipi()
 *
 * This function is for architecture or core code to speed up IPI sending. Not
 * usable from driver code.
 *
 * Return: %0 on success or negative error number on failure.
 */
int __ipi_send_mask(struct irq_desc *desc, const struct cpumask *dest)
{
    struct irq_data *data = irq_desc_get_irq_data(desc);
    struct irq_chip *chip = irq_data_get_irq_chip(data);
    unsigned int cpu;

#ifdef DEBUG
    /*
     * Minimise the overhead by omitting the checks for Linux SMP IPIs.
     * Since the callers should be arch or core code which is generally
     * trusted, only check for errors when debugging.
     */
    if (WARN_ON_ONCE(ipi_send_verify(chip, data, dest, 0)))
        return -EINVAL;
#endif
    if (chip->ipi_send_mask) {
        printk("%s: ------- ipi_send_mask\n", __func__);
        chip->ipi_send_mask(data, dest);
        printk("%s: ------- ipi_send_mask ok!\n", __func__);
        return 0;
    }

    if (irq_domain_is_ipi_per_cpu(data->domain)) {
        unsigned int base = data->irq;

        for_each_cpu(cpu, dest) {
            unsigned irq = base + cpu - data->common->ipi_offset;

            data = irq_get_irq_data(irq);
            chip->ipi_send_single(data, cpu);
        }
    } else {
        for_each_cpu(cpu, dest)
            chip->ipi_send_single(data, cpu);
    }
    PANIC("");
    return 0;
}
