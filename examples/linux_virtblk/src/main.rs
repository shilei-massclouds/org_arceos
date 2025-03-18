#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::println;

use alloc::alloc::{alloc, Layout};

extern crate alloc;

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    let ret = unsafe { clinux_start() };
    println!("cLinux ret [{}].", ret);
}

#[link(name = "clinux", kind = "static")]
unsafe extern "C" {
    fn clinux_start() -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn cl_rust_alloc(size: usize, align: usize) -> usize {
    let layout = Layout::from_size_align(size, align).unwrap();
    let ptr = unsafe { alloc(layout) };
    ptr as usize
}
