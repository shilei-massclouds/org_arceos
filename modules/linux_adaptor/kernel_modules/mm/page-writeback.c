#include <linux/writeback.h>

/*
 * Flag that puts the machine in "laptop mode". Doubles as a timeout in jiffies:
 * a full sync is triggered after this time elapses without any disk activity.
 */
int laptop_mode;

/*
 * We've spun up the disk and we're in laptop mode: schedule writeback
 * of all dirty data a few seconds from now.  If the flush is already scheduled
 * then push it back - the user is still using the disk.
 */
void laptop_io_completion(struct backing_dev_info *info)
{
    //mod_timer(&info->laptop_mode_wb_timer, jiffies + laptop_mode);
    pr_err("%s: No impl.", __func__);
}

/*
 * Called early on to tune the page writeback dirty limits.
 *
 * We used to scale dirty pages according to how total memory
 * related to pages that could be allocated for buffers.
 *
 * However, that was when we used "dirty_ratio" to scale with
 * all memory, and we don't do that any more. "dirty_ratio"
 * is now applied to total non-HIGHPAGE memory, and as such we can't
 * get into the old insane situation any more where we had
 * large amounts of dirty pages compared to a small amount of
 * non-HIGHMEM memory.
 *
 * But we might still want to scale the dirty_ratio by how
 * much memory the box has..
 */
void __init page_writeback_init(void)
{
#if 0
    BUG_ON(wb_domain_init(&global_wb_domain, GFP_KERNEL));

    cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/writeback:online",
              page_writeback_cpu_online, NULL);
    cpuhp_setup_state(CPUHP_MM_WRITEBACK_DEAD, "mm/writeback:dead", NULL,
              page_writeback_cpu_online);
#ifdef CONFIG_SYSCTL
    register_sysctl_init("vm", vm_page_writeback_sysctls);
#endif
#endif
    pr_err("%s: No impl.", __func__);
}
