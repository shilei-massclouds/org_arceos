#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::println;

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    let ret = unsafe { clinux_start() };
    println!("cLinux ret [{}].", ret);
}

#[link(name = "clinux", kind = "static")]
unsafe extern "C" {
    fn clinux_start() -> i32;
}
