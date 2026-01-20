//! Linux Adaptor for ArceOS to load and use Linux Modules.
//!
//! # Cargo Feature
//!
//! - 'linux_adaptor': Enable this module

#![no_std]

/// Initialize adaptor for linux modules.
pub fn init(_hartid: usize, _dtb_ptr: usize) {
    unsafe {
        legacy_putchar(b'A');
        legacy_putchar(b'\n');
    }
    //info!("Initialize Linux Adaptor [hartid: {} dtb_pa {:#X}] ..", hartid, dtb);
}

unsafe extern "C" {
    fn legacy_putchar(ch: u8);
}
