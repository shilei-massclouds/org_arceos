#include <linux/irq.h>

cpumask_var_t irq_default_affinity;

void enable_percpu_irq(unsigned int irq, unsigned int type)
{
    pr_err("%s: No impl. irq(%u) type(%u)\n", __func__, irq, type);
}
