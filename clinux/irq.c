#include <linux/printk.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include "booter.h"

int platform_get_irq(struct platform_device *dev, unsigned int num)
{
    int irq = 3;
    printk("---------> %s: Note impl it. num(%u) return (%d)\n",
           __func__, num, irq);
    return irq;
}

int request_threaded_irq(unsigned int irq, irq_handler_t handler,
             irq_handler_t thread_fn, unsigned long irqflags,
             const char *devname, void *dev_id)
{
    // The arg handler maybe be 'vm_interrupt'.
    printk("---------> %s: Note impl it.\n", __func__);
    printk("irq(%u) handler(%lx) thread_fn(%lx) irqflags(%lx) devname(%s)\n",
           irq, (unsigned long)handler, (unsigned long)thread_fn, irqflags, devname);
    return 0;
}
