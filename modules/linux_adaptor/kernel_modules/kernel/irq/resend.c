#include <linux/irq.h>

#ifdef CONFIG_HARDIRQS_SW_RESEND
/* hlist_head to handle software resend of interrupts: */
static HLIST_HEAD(irq_resend_list);
static DEFINE_RAW_SPINLOCK(irq_resend_lock);

void clear_irq_resend(struct irq_desc *desc)
{
    raw_spin_lock(&irq_resend_lock);
    hlist_del_init(&desc->resend_node);
    raw_spin_unlock(&irq_resend_lock);
}

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
