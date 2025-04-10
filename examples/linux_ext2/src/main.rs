#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::println;

use alloc::alloc::{alloc, Layout};
use alloc::vec::Vec;
use alloc::string::String;
use axstd::os::arceos::modules::axconfig;
use axstd::os::arceos::modules::axalloc::global_allocator;
use axstd::os::arceos::modules::axhal::mem::PAGE_SIZE_4K;
use axstd::os::arceos::modules::axhal::time::busy_wait;
use axstd::os::arceos::modules::axfs::init_filesystems_clinux;

extern crate alloc;

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    use core::time::Duration;

    let ret = unsafe { clinux_init() };
    println!("cLinux init [{}].", ret);

    /*&
    init_filesystems_clinux();

    let pwd = axstd::env::current_dir().unwrap();
    println!("{}", &pwd);

    let is_dir = axstd::fs::metadata(&pwd).unwrap().is_dir();
    if !is_dir {
        panic!("is file!");
        //return show_entry_info(pwd, pwd);
    }

    let mut entries = axstd::fs::read_dir(&pwd).unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect::<Vec<_>>();
    entries.sort();

    for entry in &entries {
        println!("{}", &entry);
    }

    println!("'ls' fat32 Ok. entrys[{}]", entries.len());
    */

    //let ret = unsafe { cl_read_block(0) };
    //println!("cLinux read_block [{}].", ret);
}

#[link(name = "clinux", kind = "static")]
unsafe extern "C" {
    fn clinux_init() -> i32;
    //fn cl_read_block(blk_nr: i32) -> i32;
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
