#include <linux/irq.h>

#ifdef CONFIG_HARDIRQS_SW_RESEND
void irq_resend_init(struct irq_desc *desc)
{
    INIT_HLIST_NODE(&desc->resend_node);
}
#endif

/*
 * IRQ resend
 *
 * Is called with interrupts disabled and desc->lock held.
 */
int check_irq_resend(struct irq_desc *desc, bool inject)
{
    pr_notice("%s: No impl.\n", __func__);
    return 0;
}
