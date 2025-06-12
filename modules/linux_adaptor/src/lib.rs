//! Linux Adaptor for ArceOS to load and use Linux Modules.
//!
//! # Cargo Feature
//!
//! - 'linux_adaptor': Enable this module

#![no_std]

#[macro_use]
extern crate axlog;
extern crate alloc;

mod export;

/// Initialize Linux modules.
pub fn init_linux_modules() {
    info!("Initialize Linux modules...");

    /* Prepare handler for plic */
    prepare_ext_interrupt();

    let ret = unsafe { clinux_init() };
    info!("cLinux init [{}].", ret);
}

#[cfg(target_arch = "riscv64")]
fn prepare_ext_interrupt() {
    // NOTE: Define EXT_IRQ_NUM for various arch in axhal.
    // `Interrupt` bit in `scause`
    const INTC_IRQ_BASE: usize = 1 << (usize::BITS - 1);
    const EXT_IRQ_NUM: usize = INTC_IRQ_BASE + 9;

    axhal::irq::register_handler(EXT_IRQ_NUM, || {
        info!("Handle ext interrupt ...");
        unsafe { plic_handle_irq() };
    });
}

#[link(name = "clinux", kind = "static")]
unsafe extern "C" {
    fn clinux_init() -> i32;
}

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn plic_handle_irq();
}
