#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/scs.h>
#include <linux/seq_file.h>
#include <linux/fwnode.h>
#include <asm/sbi.h>
#include <asm/smp.h>
#include <asm/softirq_stack.h>
#include <asm/stacktrace.h>

#include "adaptor.h"

static struct fwnode_handle *(*__get_intc_node)(void);

void riscv_set_intc_hwnode_fn(struct fwnode_handle *(*fn)(void))
{
    __get_intc_node = fn;
}

struct fwnode_handle *riscv_get_intc_hwnode(void)
{
    if (__get_intc_node)
        return __get_intc_node();

    return NULL;
}

void __init init_IRQ(void)
{
#if 0
    init_irq_scs();
    init_irq_stacks();
#endif
    irqchip_init();
    if (!handle_arch_irq)
        PANIC("No interrupt controller found.");
    //sbi_ipi_init();
}
