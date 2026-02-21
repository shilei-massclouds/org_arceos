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
        unflatten_device_tree();
    }
}

/// Prepare utilities for user-app.
pub fn prepare_for_uapp() {
}

unsafe extern "C" {
    fn cl_early_init(hartid: usize, dtb_pa: usize);
    fn unflatten_device_tree();
}
