//! Linux Adaptor for ArceOS to load and use Linux Modules.
//!
//! # Cargo Feature
//!
//! - 'linux_adaptor': Enable this module

#![no_std]

#[macro_use]
extern crate axlog;
extern crate alloc;

use alloc::alloc::{alloc, Layout};
use axconfig::plat::PHYS_VIRT_OFFSET;
use axhal::mem::PAGE_SIZE_4K;
use axalloc::global_allocator;

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
        error!("Handle ext interrupt ...");
        unsafe { plic_handle_irq() };
    });
}

#[link(name = "clinux", kind = "static")]
unsafe extern "C" {
    fn clinux_init() -> i32;
}

/*
 * Expose to clinux
 */

/// Offset between VirtAddr and PhysAddr in kernel aspace.
#[unsafe(no_mangle)]
static va_pa_offset: usize = PHYS_VIRT_OFFSET;

/// Alloc bytes.
#[unsafe(no_mangle)]
pub extern "C" fn cl_rust_alloc(size: usize, align: usize) -> usize {
    let layout = Layout::from_size_align(size, align).unwrap();
    let ptr = unsafe { alloc(layout) };
    ptr as usize
}

/// Dealloc bytes.
#[unsafe(no_mangle)]
pub extern "C" fn cl_rust_dealloc(addr: usize) {
    info!("No impl. We don't know layout for addr '{:#x}'.", addr);
}

/// Alloc pages.
#[unsafe(no_mangle)]
pub extern "C" fn cl_alloc_pages(size: usize, align: usize) -> usize {
    assert!(size > 0);
    assert_eq!(size % PAGE_SIZE_4K, 0);
    assert!(align > 0);
    assert_eq!(align % PAGE_SIZE_4K, 0);
    let count = size >> 12;
    global_allocator().alloc_pages(count, align).unwrap()
}

unsafe extern "C" {
    fn plic_handle_irq();
}
