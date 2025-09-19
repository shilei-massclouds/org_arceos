#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/scs.h>
#include <linux/seq_file.h>
#include <asm/sbi.h>
#include <asm/smp.h>
#include <asm/softirq_stack.h>
#include <asm/stacktrace.h>

void __init init_IRQ(void)
{
#if 0
    init_irq_scs();
    init_irq_stacks();
#endif
    irqchip_init();
    if (!handle_arch_irq)
        panic("No interrupt controller found.");
    //sbi_ipi_init();
}
