//! Linux Adaptor for ArceOS to load and use Linux Modules.
//!
//! # Cargo Feature
//!
//! - 'linux_adaptor': Enable this module

#![no_std]

#[macro_use]
extern crate axlog;

mod traps;

/// Initialize adaptor for linux modules.
pub fn init(hartid: usize, dtb_pa: usize) {
    ax_println!("\nWith Linux Adaptor: hartid = {hartid}, dtb_pa = {dtb_pa:#X}");
    unsafe {
        cl_early_init(hartid, dtb_pa);
    }
}

unsafe extern "C" {
    fn cl_early_init(hartid: usize, dtb_pa: usize);
}
