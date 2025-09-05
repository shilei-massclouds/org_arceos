#include <linux/string.h>
#include <linux/printk.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/sched/init.h>
#include <linux/buffer_head.h>
#include <linux/of.h>
#include <linux/cpu.h>
#include <linux/ftrace.h>

#include "mm/slab.h"
#include "base/base.h"
#include "block/blk.h"
#include "adaptor.h"

//#define TEST_BLOCK
//#define TEST_EXT2
//#define TEST_EXT4

extern void cl_riscv_intc_init(struct device_node *node,
                               struct device_node *parent);

extern void cl_crc32_mod_init(void);
extern void cl_crc32c_mod_init(void);
extern int cl_blake2s_mod_init(void);

extern int cl_plic_init(void);

extern void cl_virtio_init();
extern void cl_virtio_mmio_init();
extern void cl_virtio_blk_init();

extern void cl_blkdev_init(void);
extern void cl_init_bio(void);
extern void cl_sg_pool_init(void);
extern int cl_default_bdi_init(void);

extern int cl_journal_init(void);
extern int cl_ext4_init_fs(void);

extern void cl_invoke_softirq(void);
extern void cl_blk_timeout_init(void);

extern void test_block(void);
extern void test_ext4();

int clinux_starting = 0;
int clinux_started = 0;

bool static_key_initialized __read_mostly;

int clinux_init(void)
{
    printk("cLinux base is starting ...\n");

    clinux_starting = 1;

    /* Static keys and static calls are needed by LSMs */
    jump_label_init();
    random_init_early("");
    vfs_caches_init_early();

    cl_blk_timeout_init();

    cl_crc32_mod_init();
    cl_crc32c_mod_init();
    cl_blake2s_mod_init();

    random_init();

    //kmem_cache_init();
    setup_per_cpu_areas();
    boot_cpu_init();
    pagecache_init();
    early_trace_init();
    sched_init();
    radix_tree_init();
    maple_tree_init();
    trace_init();
    buses_init();
    buffer_init();
    vfs_caches_init();
    workqueue_init_early();

    cl_init_bio();
    cl_sg_pool_init();

    init_timers();
    workqueue_init();
    workqueue_init_topology();
    cl_default_bdi_init();

    {
        static struct device_node riscv_intc_node;
        riscv_intc_node.name = "riscv_intc";
        cl_riscv_intc_init(&riscv_intc_node, NULL);
        if (handle_arch_irq == NULL) {
            PANIC("No handle_arch_irq.");
        }
    }

    clinux_started = 1;

    // Note: Refer to old cl_irq_init in irq.c.
    cl_plic_init();

    // block/blk-core.c
    blk_dev_init();

    // block/fops.c
    cl_blkdev_init();

    cl_virtio_init();
    cl_virtio_mmio_init();
    cl_virtio_blk_init();

#ifdef TEST_BLOCK
    test_block();
#endif

    printk("====== Journal init ======\n");
    cl_journal_init();
    printk("====== Ext4 init ======\n");
    cl_ext4_init_fs();

    printk("====== Ext4 mount ======\n");
    if (cl_mount("ext4", "/dev/root") < 0) {
        PANIC("bad ext4 root.");
    }

#ifdef TEST_EXT4
    printk("====== Ext4 test ======\n");
    test_ext4();
    ftrace_dump(DUMP_ALL);
    PANIC("Reach here!");
#endif

    return 0;
}

void call_handle_arch_irq(unsigned long cause)
{
    struct pt_regs regs;
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
