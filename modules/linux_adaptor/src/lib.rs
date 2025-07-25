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

use axhal::mem::virt_to_phys;
use memory_addr::{pa, MemoryAddr};
use axconfig::plat::{PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE};

/// Initialize Linux modules.
pub fn init_linux_modules() {
    info!("Initialize Linux modules...");

    /* Prepare handler for plic */
    prepare_ext_interrupt();

    /* All pages range for mem_map */
    let start = virt_to_phys((_skernel as usize).into()).align_up_4k();
    let end = pa!(PHYS_MEMORY_BASE + PHYS_MEMORY_SIZE).align_down_4k();
    unsafe { init_mem_map(start.into(), end.into()) };

    let task_ptr = unsafe {
        init_current(axtask::current().id().as_u64())
    };
    axtask::current().set_private(task_ptr);
    error!("Linux init_tasik pointer({:#x})", task_ptr);

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
    fn init_current(tid: u64) -> u64;
    fn clinux_init() -> i32;
    fn init_mem_map(pa_start: usize, pa_end: usize) -> i32;
}

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn plic_handle_irq();
}

unsafe extern "C" {
    fn _skernel();
}
