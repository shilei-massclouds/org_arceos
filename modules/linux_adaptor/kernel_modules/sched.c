#include <linux/printk.h>
#include <linux/sched.h>

#include "booter.h"

void __might_sleep(const char *file, int line, int preempt_offset)
{
    printk("%s: \n", __func__);
}

static struct task_struct task_dummy;
struct task_struct *get_current(void)
{
    return &task_dummy;
}
