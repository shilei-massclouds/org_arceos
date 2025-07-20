#include <linux/irq.h>

#include "internals.h"
#include "../adaptor.h"

struct irq_data *irq_get_irq_data(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);

    return desc ? &desc->irq_data : NULL;
}

void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set)
{
    pr_err("%s: No impl.\n", __func__);
}

static void
__irq_do_set_handler(struct irq_desc *desc, irq_flow_handler_t handle,
             int is_chained, const char *name)
{
    pr_err("%s: No impl.\n", __func__);
    if (!handle) {
        PANIC("No handle.");
    }
    if (!desc) {
        PANIC("No desc.");
    }

    desc->handle_irq = handle;
    desc->name = name;
}

void
__irq_set_handler(unsigned int irq, irq_flow_handler_t handle, int is_chained,
          const char *name)
{
    unsigned long flags;
    struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, 0);

    if (!desc)
        return;

    __irq_do_set_handler(desc, handle, is_chained, name);
    irq_put_desc_busunlock(desc, flags);
}
