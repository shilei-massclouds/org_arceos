//! Interrupt management.

use axcpu::trap::{IRQ, register_trap_handler};

pub use axplat::irq::{handle, register, set_enable, unregister};

#[cfg(feature = "ipi")]
pub use axplat::irq::{IpiTarget, send_ipi};

#[cfg(feature = "ipi")]
pub use axconfig::devices::IPI_IRQ;

/// IRQ handler.
///
/// # Warn
///
/// Make sure called in an interrupt context or hypervisor VM exit handler.
#[register_trap_handler(IRQ)]
pub fn irq_handler(vector: usize) -> bool {
    let guard = kernel_guard::NoPreempt::new();
    handle(vector);
    drop(guard); // rescheduling may occur when preemption is re-enabled.
    true
}

pub fn init_early() {
    // FixMe: move `init_IRQ` into axplat::irq::init_early()
    #[cfg(feature = "linux-adaptor")]
    unsafe {
        /*
         * irq depends on radix && maple
         */
        radix_tree_init();
        maple_tree_init();

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

unsafe extern "C" {
    fn radix_tree_init();
    fn maple_tree_init();
    fn early_irq_init();
    fn init_IRQ();
    fn tick_init();
    fn init_timers();
    fn hrtimers_init();
    fn softirq_init();
    fn timekeeping_init();
    fn time_init();
    fn random_init();
}
