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
use axconfig::plat::{PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE, PHYS_VIRT_OFFSET};

/// Initialize Linux modules.
pub fn init_linux_modules() {
    info!("Initialize Linux modules...");

    /* Offset between VirtAddr and PhysAddr in kernel aspace. */
    unsafe { setup_paging(PHYS_VIRT_OFFSET) };

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
    info!("Linux init task set pointer({:#x})", task_ptr);

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
        unsafe { call_handle_arch_irq(EXT_IRQ_NUM as usize) };
    });
}

unsafe extern "C" {
    fn init_current(tid: u64) -> u64;
    fn clinux_init() -> i32;
    fn init_mem_map(pa_start: usize, pa_end: usize) -> i32;
}

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn call_handle_arch_irq(cause: usize);
    fn setup_paging(va_pa_offset: usize);
}

unsafe extern "C" {
    fn _skernel();
}
