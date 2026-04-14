#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

extern crate alloc;

mod init_args;
mod mm;

#[cfg(feature = "axstd")]
use axstd::println;

use init_args::CStringArray;
use core::ffi::c_char;

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    println!("Hello, LK!");

    ax_prepare_console_node();
    ax_prepare_stdio_from_console();

    let argv = ["init.sh"];
    let envp = ["HOME=/", "TERM=linux"];
    ax_run_init_process("/bin/sh", &argv, &envp);
}

fn ax_prepare_console_node() {
    let ret = unsafe { cl_prepare_console_node() };
    if ret != 0 {
        panic!("failed to prepare /dev/console: {}", ret);
    }
}

fn ax_prepare_stdio_from_console() {
    let ret = unsafe { cl_prepare_stdio_from_console() };
    if ret != 0 {
        panic!("failed to prepare stdio from /dev/console: {}", ret);
    }
}

fn ax_run_init_process(filename: &str, args: &[&str], envp: &[&str]) {
    let argv_storage = CStringArray::new(Some(filename), args);
    let argv = argv_storage.as_cstr_array();

    let envp_storage = CStringArray::new(None, envp);
    let envp = envp_storage.as_cstr_array();

    let ret = unsafe {
        cl_run_init_process(
            argv[0],
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    if ret != 0 {
        panic!("No working init found.  Try passing init= option to kernel. \
            See Linux Documentation/admin-guide/init.rst for guidance.");
    }
}

unsafe extern "C" {
    fn cl_prepare_console_node() -> i32;
    fn cl_prepare_stdio_from_console() -> i32;
    fn cl_run_init_process(
        init_filename: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;
}
