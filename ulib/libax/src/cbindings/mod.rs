#[macro_use]
mod utils;

#[cfg(feature = "fs")]
mod fs;
#[cfg(feature = "alloc")]
mod malloc;

/// cbindgen:ignore
#[rustfmt::skip]
#[path = "./ctypes_gen.rs"]
#[allow(dead_code, non_camel_case_types)]
mod ctypes;

use crate::io::Write;
use core::ffi::{c_char, c_int};

#[no_mangle]
pub extern "C" fn ax_srand(seed: u32) {
    crate::rand::srand(seed);
}

#[no_mangle]
pub extern "C" fn ax_rand_u32() -> u32 {
    crate::rand::rand_u32()
}

#[no_mangle]
pub extern "C" fn ax_print_str(buf: *const c_char, count: usize) -> c_int {
    if buf.is_null() {
        return -axerrno::LinuxError::EFAULT.code();
    }
    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, count as _) };
    crate::io::stdout().write(bytes).unwrap() as _
}

#[no_mangle]
pub extern "C" fn ax_panic() -> ! {
    panic!()
}

#[cfg(feature = "alloc")]
pub use self::malloc::{ax_free, ax_malloc};

#[cfg(feature = "fs")]
pub use self::fs::{
    ax_close, ax_fstat, ax_getcwd, ax_lseek, ax_lstat, ax_open, ax_read, ax_stat, ax_write,
};
