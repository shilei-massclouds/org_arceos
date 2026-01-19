//! Linux Adaptor for ArceOS to load and use Linux Modules.
//!
//! # Cargo Feature
//!
//! - 'linux_adaptor': Enable this module

#![no_std]

/// Initialize adaptor for linux modules.
pub fn init(hartid: usize, dtb: usize) {
    //info!("Initialize Linux Adaptor [hartid: {} dtb_pa {:#X}] ..", hartid, dtb);
}
