#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::println;

use alloc::alloc::{alloc, Layout};
use axstd::os::arceos::modules::axconfig;
use axstd::os::arceos::modules::axalloc::global_allocator;
use axstd::os::arceos::modules::axhal::mem::PAGE_SIZE_4K;

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
static va_pa_offset: usize = axconfig::PHYS_VIRT_OFFSET;

#[unsafe(no_mangle)]
pub extern "C" fn cl_rust_alloc(size: usize, align: usize) -> usize {
    let layout = Layout::from_size_align(size, align).unwrap();
    let ptr = unsafe { alloc(layout) };
    ptr as usize
}

#[unsafe(no_mangle)]
pub extern "C" fn cl_rust_dealloc(addr: usize) {
    println!("No impl. We don't know layout for addr '{:#x}'.", addr);
}

#[unsafe(no_mangle)]
pub extern "C" fn cl_alloc_pages(size: usize, align: usize) -> usize {
    assert!(size > 0);
    assert_eq!(size % PAGE_SIZE_4K, 0);
    assert!(align > 0);
    assert_eq!(align % PAGE_SIZE_4K, 0);
    let count = size >> 12;
    global_allocator().alloc_pages(count, align).unwrap()
}
