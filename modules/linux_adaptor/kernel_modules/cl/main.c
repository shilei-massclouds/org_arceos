#include <linux/string.h>
#include <linux/printk.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/sched/init.h>
#include <linux/buffer_head.h>
#include <linux/of.h>
#include <linux/cpu.h>
#include <linux/of_fdt.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <asm/fixmap.h>

// Only for riscv64
#include <asm/sbi.h>

#include "../mm/slab.h"
#include "../drivers/base/base.h"
//#include "block/blk.h"
#include "adaptor.h"

#define DP1000

//#define TEST_BLOCK
#define TEST_EXT4
//#define BENCH_MARK

extern void cl_do_initcalls(void);
extern void cl_invoke_softirq(void);

extern void __init
create_fdt_early_page_table(uintptr_t fix_fdt_va,
                            uintptr_t dtb_pa);

extern void test_block(void);
extern void test_ext4();
extern void bench_ext4();

int clinux_starting = 0;
int clinux_started = 0;

bool static_key_initialized __read_mostly;

unsigned long cl_fixaddr_start;

int clinux_init(unsigned long hartid, phys_addr_t dt_phys)
{
    printk("cLinux base is starting hartid[0x%lx] ...\n", hartid);
    boot_cpu_hartid = hartid;
    cl_fixaddr_start = FIXADDR_START;

    /* Setup early mapping for FDT early scan */
    create_fdt_early_page_table(__fix_to_virt(FIX_FDT), dt_phys);

    clinux_starting = 1;

    smp_setup_processor_id();
    boot_cpu_init();

    early_init_dt_verify(dtb_early_va, dt_phys);
    early_init_dt_scan_chosen(boot_command_line);

    setup_arch(NULL /* cmdline_p */);

    // Only for riscv64
    sbi_init();
    unflatten_device_tree();
    setup_smp();

    setup_nr_cpu_ids();
    setup_per_cpu_areas();

    printk("Kernel command line: %s\n", boot_command_line);

    random_init_early("");
    vfs_caches_init_early();

    random_init();

    kmem_cache_init();
    pagecache_init();
#ifndef DP1000
    early_trace_init();
#endif
    sched_init();
    radix_tree_init();
    maple_tree_init();
    trace_init();
    workqueue_init_early();
    devices_init();
    buses_init();
    classes_init();
    firmware_init();
    platform_bus_init();
    buffer_init();
    vfs_caches_init();

    init_timers();
    workqueue_init();
    workqueue_init_topology();
    async_init();

    // NOTE: Impl it.
    //early_irq_init();
    init_IRQ();

    parse_early_param();

    clinux_started = 1;

    cl_do_initcalls();

    // Set ROOT_DEV based on linux commandline.
    printk("====== Prepare namespace ====== [%u]\n", current->pid);
    prepare_namespace();

    smp_init();

#ifdef TEST_BLOCK
    printk("====== VirtIoBlock test ======\n");
    test_block();
#endif

    printk("====== Ext4 mount ======\n");
    if (cl_mount("ext4", "/dev/root") < 0) {
        PANIC("bad ext4 root.");
    }

#ifdef TEST_EXT4
    printk("====== Ext4 test ======\n");
    test_ext4();
    //ftrace_dump(DUMP_ALL);
    PANIC("Reach here!");
#endif

#ifdef BENCH_MARK
    printk("====== Bench Mark for Ext4 ======\n");
    bench_ext4();
    PANIC("Reach here!");
#endif

    return 0;
}

void call_handle_arch_irq(unsigned long cause)
{
    struct pt_regs regs;
    if (smp_processor_id()) {
        printk("%s: cpu(%u)\n", __func__, smp_processor_id());
        PANIC("");
    }
    regs.cause = cause;
    handle_arch_irq(&regs);
}

// Refer to "__irq_exit_rcu" in [softirq.c]
void cl_handle_softirq(unsigned long irqnum)
{
    pr_debug("%s: irqnum(%u) clinux starting(%d)\n",
             __func__, irqnum, clinux_starting);
    if (clinux_started == 0) {
        return;
    }

    local_irq_disable();

    if (!in_interrupt() && local_softirq_pending())
        cl_invoke_softirq();

    // Note: consider to handle tick_irq_exit in future.
    // tick_irq_exit();
}

unsigned long cl_preemptible(void)
{
    return preemptible();
}
