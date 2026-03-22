#include <linux/blkdev.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/vmalloc.h>

#include "adaptor.h"

unsigned long linux_virt_to_phys(unsigned long va)
{
    if (is_vmalloc_addr((void *)va)) {
        struct page *page = vmalloc_to_page((void *)va);
        return page_to_phys(page) + offset_in_page(va);
    }
    return __pa(va);
}

unsigned long linux_phys_to_virt(unsigned long pa)
{
    return (unsigned long) __va(pa);
}

void *linux_kmalloc_kernel(size_t size, unsigned int align)
{
    void *ret = kmalloc(size, GFP_KERNEL);
    if (ret == NULL) {
        /* size is too large, use vmalloc. BUT it is WRONG. */
        /*
         * FixMe:
         * linux_kmalloc_kernel serves for Rust GlobalAllocator:alloc, which
         * disables irqs and doesn't allow to sleep. But vmalloc MAY sleep.
         */
        printk("kmalloc.size: 0x%lx, it's too large, use vmalloc instead.\n", size);
        local_irq_enable();     /* FixMe: This is just a temporary trick. */
        ret = vmalloc(size);
        local_irq_disable();    /* FixMe: This is just a temporary trick. */
    }
    CL_ASSERT(IS_ALIGNED((unsigned long)ret, align),
              "kmalloc error: NOT aligned");
    return ret;
}

struct task_struct *linux_current()
{
    return current;
}

unsigned long linux_my_cpu_offset()
{
    return __my_cpu_offset;
}

void set_current_need_resched()
{
    set_tsk_need_resched(current);
}

pid_t linux_kernel_thread(int (*fn)(void *), void *opaque)
{
    return kernel_thread(fn, opaque, NULL, CLONE_FS | CLONE_FILES);
}

/*
 * Return 0 when the timer has expired
 * otherwise the remaining time in jiffies.
 */
int swait_timeout_until(struct swait_queue_head *wq,
                        long msecs,
                        int (*condition)(void *),
                        void *opaque)
{
    long timeout = msecs_to_jiffies(msecs);
    return swait_event_timeout_exclusive(*wq, condition(opaque), timeout);
}

void swait_until(struct swait_queue_head *wq,
                 int (*condition)(void *),
                 void *opaque)
{
    swait_event_exclusive(*wq, condition(opaque));
}

void swait_uninterruptible(struct swait_queue_head *wq)
{
    struct swait_queue wait;
    INIT_LIST_HEAD(&wait.task_list);

    if (prepare_to_swait_event(wq, &wait, TASK_UNINTERRUPTIBLE)) {
        return;
    }

    schedule();
    finish_swait(wq, &wait);
}

int swait_count_sleepers(struct swait_queue_head *wq)
{
	smp_mb();
	return list_count_nodes(&wq->task_list);
}

/*
 * Check or init swait itself.
 */
void swait_check_or_init(struct swait_queue_head *wq)
{
	unsigned long flags;

    BUG_ON(!wq);

	raw_spin_lock_irqsave(&wq->lock, flags);
    if (wq->task_list.next == NULL && wq->task_list.prev == NULL) {
        INIT_LIST_HEAD(&wq->task_list);
    }
	raw_spin_unlock_irqrestore(&wq->lock, flags);
}

int linux_set_nice(pid_t pid, long nice)
{
    struct task_struct *p = find_task_by_vpid(pid);
    if (p == NULL) {
        return -ESRCH;
    }
    set_user_nice(p, nice);
    return 0;
}

/* Export to rust crate 'memblock'. */
void *linux_memblock_alloc(phys_addr_t size, phys_addr_t align)
{
    return memblock_alloc_try_nid(size, align, MEMBLOCK_LOW_LIMIT,
                MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_NO_NODE);
}

int cl_cpu_id(void)
{
    return smp_processor_id();
}

unsigned int cl_get_nr_cpu_ids(void)
{
    return nr_cpu_ids;
}

void *cl_this_cpu_ptr(void *pcp, int size)
{
    switch (size) {
    case 1:
        return this_cpu_ptr((unsigned char *)pcp);
    case 2:
        return this_cpu_ptr((unsigned short *)pcp);
    case 4:
        return this_cpu_ptr((unsigned int *)pcp);
    case 8:
        return this_cpu_ptr((unsigned long *)pcp);
    default:
    }
    PANIC("unknown type size!");
}

dev_t cl_lookup_bdev(const char *dname)
{
    dev_t devt = 0;
    if (early_lookup_bdev(dname, &devt)) {
        PANIC("No block device.");
    }
    return devt;
}

int cl_bdev_size(dev_t devt)
{
	struct block_device *bdev;
	bdev = blkdev_get_no_open(devt);
	if (!bdev || !bdev->bd_disk) {
        PANIC("no bdev!");
    }
    return get_capacity(bdev->bd_disk) * bdev_logical_block_size(bdev);
}

int cl_bdev_logic_block_size(dev_t devt)
{
	struct block_device *bdev;
	bdev = blkdev_get_no_open(devt);
	if (!bdev || !bdev->bd_disk) {
        PANIC("no bdev!");
    }
    return bdev_logical_block_size(bdev);
}

int cl_read_block(dev_t devt, void *buf, size_t count, loff_t pos)
{
    int ret;
    struct file *fp;
    fp = bdev_file_open_by_dev(devt, BLK_OPEN_READ, NULL, NULL);
    if (IS_ERR(fp)) {
        PANIC("failed to open block device");
    }

    ret = kernel_read(fp, buf, count, &pos);
    if (ret < 0) {
        PANIC("failed to read block device");
    }
    bdev_fput(fp);

    return ret;
}

int cl_write_block(dev_t devt, void *buf, size_t count, loff_t pos)
{
    int ret;
    struct file *fp;
    loff_t old_pos = pos;

    fp = bdev_file_open_by_dev(devt, BLK_OPEN_WRITE, NULL, NULL);
    if (IS_ERR(fp)) {
        PANIC("failed to open block device");
    }

    ret = kernel_write(fp, buf, count, &pos);
    if (ret < 0) {
        PANIC("failed to write block device");
    }

    if (sync_file_range(fp, old_pos, count, SYNC_FILE_RANGE_WRITE_AND_WAIT)) {
        PANIC("failed to sync block device");
    }

    bdev_fput(fp);

    return ret;
}

dev_t cl_early_lookup_bdev(const char *name)
{
    dev_t devt = 0;

    if (early_lookup_bdev(name, &devt)) {
        return 0;
    }
    return devt;
}

int cl_irqs_disabled(void)
{
    return irqs_disabled();
}
