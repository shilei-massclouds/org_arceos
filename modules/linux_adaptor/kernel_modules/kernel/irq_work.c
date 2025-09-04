#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/irq_work.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/irqflags.h>
#include <linux/sched.h>
#include <linux/tick.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/smp.h>
#include <linux/smpboot.h>
#include <asm/processor.h>
#include <linux/kasan.h>

#include <trace/events/ipi.h>
#include "../adaptor.h"

/* Enqueue the irq work @work on the current CPU */
bool irq_work_queue(struct irq_work *work)
{
#if 0
    /* Only queue if not already pending */
    if (!irq_work_claim(work))
        return false;

    /* Queue the entry and raise the IPI if needed. */
    preempt_disable();
    __irq_work_queue_local(work);
    preempt_enable();

    return true;
#endif
    PANIC("");
}
