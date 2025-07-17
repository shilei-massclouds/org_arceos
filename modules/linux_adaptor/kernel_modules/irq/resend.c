#include <linux/irq.h>

#ifdef CONFIG_HARDIRQS_SW_RESEND
void irq_resend_init(struct irq_desc *desc)
{
    INIT_HLIST_NODE(&desc->resend_node);
}
#endif
