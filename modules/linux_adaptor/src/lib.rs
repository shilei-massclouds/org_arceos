//! Linux Adaptor for ArceOS to load and use Linux Modules.
//!
//! # Cargo Feature
//!
//! - 'linux_adaptor': Enable this module

#![no_std]

#[macro_use]
extern crate axlog;

use axconfig::plat::PHYS_VIRT_OFFSET;

/// Initialize Linux modules.
pub fn init_linux_modules() {
    info!("Initialize Linux modules...");
    let ret = unsafe { clinux_init() };
    info!("cLinux init [{}].", ret);
    unimplemented!();
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
