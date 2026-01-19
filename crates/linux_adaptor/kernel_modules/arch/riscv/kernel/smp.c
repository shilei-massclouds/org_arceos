#include <linux/cpu.h>
#include <linux/clockchips.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/kexec.h>
#include <linux/kgdb.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/irq_work.h>
#include <linux/nmi.h>

#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>

#include "adaptor.h"

enum ipi_message_type {
    IPI_RESCHEDULE,
    IPI_CALL_FUNC,
    IPI_CPU_STOP,
    IPI_CPU_CRASH_STOP,
    IPI_IRQ_WORK,
    IPI_TIMER,
    IPI_CPU_BACKTRACE,
    IPI_KGDB_ROUNDUP,
    IPI_MAX
};

unsigned long __cpuid_to_hartid_map[NR_CPUS] __ro_after_init = {
    [0 ... NR_CPUS-1] = INVALID_HARTID
};

static struct irq_desc *ipi_desc[IPI_MAX] __read_mostly;
static int ipi_virq_base __ro_after_init;
static int nr_ipi __ro_after_init = IPI_MAX;
static DEFINE_PER_CPU_READ_MOSTLY(int, ipi_dummy_dev);

static void ipi_stop(void)
{
    set_cpu_online(smp_processor_id(), false);
    while (1)
        wait_for_interrupt();
}

static inline void ipi_cpu_crash_stop(unsigned int cpu, struct pt_regs *regs)
{
    unreachable();
}

static irqreturn_t handle_IPI(int irq, void *data)
{
    unsigned int cpu = smp_processor_id();
    int ipi = irq - ipi_virq_base;

    switch (ipi) {
    case IPI_RESCHEDULE:
        scheduler_ipi();
        break;
    case IPI_CALL_FUNC:
        generic_smp_call_function_interrupt();
        break;
    case IPI_CPU_STOP:
        ipi_stop();
        break;
    case IPI_CPU_CRASH_STOP:
        ipi_cpu_crash_stop(cpu, get_irq_regs());
        break;
    case IPI_IRQ_WORK:
        irq_work_run();
        break;
#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
    case IPI_TIMER:
        tick_receive_broadcast();
        break;
#endif
    case IPI_CPU_BACKTRACE:
        nmi_cpu_backtrace(get_irq_regs());
        break;
    case IPI_KGDB_ROUNDUP:
        kgdb_nmicallback(cpu, get_irq_regs());
        break;
    default:
        pr_warn("CPU%d: unhandled IPI%d\n", cpu, ipi);
        break;
    }

    return IRQ_HANDLED;
}

int riscv_hartid_to_cpuid(unsigned long hartid)
{
    int i;

    for (i = 0; i < NR_CPUS; i++)
        if (cpuid_to_hartid_map(i) == hartid)
            return i;

    return -ENOENT;
}

void __init smp_setup_processor_id(void)
{
    cpuid_to_hartid_map(0) = boot_cpu_hartid;
}

static void send_ipi_single(int cpu, enum ipi_message_type op)
{
    printk("%s: ipi cpu(%u) type(%u)\n", __func__, cpu, op);
    __ipi_send_mask(ipi_desc[op], cpumask_of(cpu));
}

void arch_send_call_function_single_ipi(int cpu)
{
    send_ipi_single(cpu, IPI_CALL_FUNC);
}

bool riscv_ipi_have_virq_range(void)
{
    return (ipi_virq_base) ? true : false;
}

void riscv_ipi_set_virq_range(int virq, int nr)
{
    int i, err;

    if (WARN_ON(ipi_virq_base))
        return;

    WARN_ON(nr < IPI_MAX);
    nr_ipi = min(nr, IPI_MAX);
    ipi_virq_base = virq;

    /* Request IPIs */
    for (i = 0; i < nr_ipi; i++) {
        err = request_percpu_irq(ipi_virq_base + i, handle_IPI,
                     "IPI", &ipi_dummy_dev);
        WARN_ON(err);

        ipi_desc[i] = irq_to_desc(ipi_virq_base + i);
        irq_set_status_flags(ipi_virq_base + i, IRQ_HIDDEN);
    }

    /* Enabled IPIs for boot CPU immediately */
    riscv_ipi_enable();
}

void riscv_ipi_enable(void)
{
    int i;

    if (WARN_ON_ONCE(!ipi_virq_base))
        return;

    for (i = 0; i < nr_ipi; i++)
        enable_percpu_irq(ipi_virq_base + i, 0);
}
