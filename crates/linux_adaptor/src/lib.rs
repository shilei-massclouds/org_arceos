//! Linux Adaptor for ArceOS to load and use Linux Modules.
//!
//! # Cargo Feature
//!
//! - 'linux_adaptor': Enable this module

#![no_std]

#[macro_use]
extern crate axlog;

/// Initialize adaptor at the early stage for linux modules.
pub fn init_early(hartid: usize, dtb_pa: usize) {
    ax_println!("\nWith Linux Adaptor: hartid = {hartid}, dtb_pa = {dtb_pa:#X}");
    unsafe {
        cl_early_init(hartid, dtb_pa);
    }
}

/// Initialize adaptor at the later stage for linux modules.
pub fn init_later(_hartid: usize, _dtb_pa: usize) {
    unsafe {
        jump_label_init();
        unflatten_device_tree();
        misc_mem_init();
        setup_smp();
        riscv_fill_hwcap();

        setup_nr_cpu_ids();
        setup_per_cpu_areas();
        boot_cpu_hotplug_init();
        random_init_early(/* command_line */);
    }
}

pub fn init_irq_earlier() {
    unsafe {
        /*
         * irq depends on radix && maple
         */
        radix_tree_init();
        maple_tree_init();

        /*
         * Allow workqueue creation and work item queueing/cancelling
         * early.  Work item execution depends on kthreads and starts after
         * workqueue_init().
         */
        workqueue_init_early();
        rcu_init();

        /* init some links before init_ISA_irqs() */
        early_irq_init();
        init_IRQ();
        tick_init();
        //rcu_init_nohz();
        init_timers();
        //srcu_init();
        hrtimers_init();

        softirq_init();
        timekeeping_init();
        time_init();

        /* This must be after timekeeping is initialized */
        random_init();
    }
}

/// Prepare utilities for user-app.
pub fn prepare_for_userboot() {
    #[cfg(feature = "irq")]
    unsafe {
        init_userboot_earlier();
    }
}

unsafe extern "C" {
    fn cl_early_init(hartid: usize, dtb_pa: usize);
    fn unflatten_device_tree();
    fn setup_smp();
    fn riscv_fill_hwcap();
    fn misc_mem_init();
    fn jump_label_init();
    fn setup_nr_cpu_ids();
    fn setup_per_cpu_areas();
    fn boot_cpu_hotplug_init();
    fn random_init_early(/* command_line */);
}

unsafe extern "C" {
    fn radix_tree_init();
    fn maple_tree_init();
    fn workqueue_init_early();
    fn rcu_init();
    fn early_irq_init();
    fn init_IRQ();
    fn tick_init();
    fn init_timers();
    fn hrtimers_init();
    fn softirq_init();
    fn timekeeping_init();
    fn time_init();
    fn random_init();
    #[allow(dead_code)]
    fn init_userboot_earlier();
}
