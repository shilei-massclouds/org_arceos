#include <linux/irq.h>

#ifdef CONFIG_GENERIC_IRQ_MULTI_HANDLER
void (*handle_arch_irq)(struct pt_regs *) __ro_after_init;
#endif

#ifdef CONFIG_GENERIC_IRQ_MULTI_HANDLER
int __init set_handle_irq(void (*handle_irq)(struct pt_regs *))
{
    if (handle_arch_irq)
        return -EBUSY;

    printk("%s: handle(%lx)\n", __func__, handle_irq);
    handle_arch_irq = handle_irq;
    return 0;
}
#endif
