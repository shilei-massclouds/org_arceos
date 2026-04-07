#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

extern crate alloc;

mod mm;

#[cfg(feature = "axstd")]
use axstd::println;

use alloc::ffi::CString;
use core::ffi::c_char;

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    println!("Hello, LK!");
    ax_run_init_process("/bin/sh");
}

fn ax_run_init_process(cmd: &str) {
    let cmd = CString::new(cmd).expect("bad int command");
    let ret = unsafe {
        cl_try_to_run_init_process(cmd.as_ptr())
    };
    if ret != 0 {
        panic!("No working init found.  Try passing init= option to kernel. \
            See Linux Documentation/admin-guide/init.rst for guidance.");
    }
}

unsafe extern "C" {
    fn cl_try_to_run_init_process(cmd: *const c_char) -> i32;
}
