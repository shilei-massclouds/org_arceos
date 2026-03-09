//! Linux Adaptor for ArceOS to load and use Linux Modules.
//!
//! # Cargo Feature
//!
//! - 'linux_adaptor': Enable this module
//!

#![no_std]

#[macro_use]
extern crate axlog;

mod state;
pub use state::{LinuxAdaptorState, advance_to};
