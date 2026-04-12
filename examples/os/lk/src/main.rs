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
    ax_prepare_console_node();
    ax_prepare_stdio_from_console();
    ax_run_init_process("/bin/sh");
}

fn ax_prepare_console_node() {
    let ret = unsafe { cl_prepare_console_node() };
    if ret != 0 {
        panic!("failed to prepare /dev/console: {}", ret);
    }
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

fn ax_prepare_stdio_from_console() {
    let ret = unsafe { cl_prepare_stdio_from_console() };
    if ret != 0 {
        panic!("failed to prepare stdio from /dev/console: {}", ret);
    }
}

unsafe extern "C" {
    fn cl_prepare_console_node() -> i32;
    fn cl_prepare_stdio_from_console() -> i32;
    fn cl_try_to_run_init_process(cmd: *const c_char) -> i32;
}
