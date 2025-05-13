//! Linux Adaptor for ArceOS to load and use Linux Modules.
//!
//! # Cargo Feature
//!
//! - 'linux_adaptor': Enable this module

#![no_std]

#[macro_use]
extern crate axlog;

/// Initialize Linux modules.
pub fn init_linux_modules() {
    info!("Initialize Linux modules...");
    unimplemented!();
}
