#include <linux/cpu.h>
#include <linux/mm.h>
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
        /* size is too large, try to use vmalloc */
        printk("kmalloc.size: 0x%lx, it's too large, use vmalloc instead.\n", size);
        ret = vmalloc(size);
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

void linux_idle_loop(pid_t pid)
{
    /*
     * The boot idle thread must execute schedule()
     * at least once to get things moving:
     */
    schedule_preempt_disabled();
    /* Call into cpu_idle with preempt disabled */
    cpu_startup_entry(CPUHP_ONLINE);
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
    printk("%s: msecs(%lu) timeout(%lu)\n", __func__, msecs, timeout);
    return swait_event_timeout_exclusive(*wq, condition(opaque), timeout);
}

void swait_until(struct swait_queue_head *wq,
                 int (*condition)(void *),
                 void *opaque)
{
    swait_event_exclusive(*wq, condition(opaque));
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

/* FixMe: impl it. */
void ax_handle_irq(unsigned long cause)
{
    PANIC("");
}
