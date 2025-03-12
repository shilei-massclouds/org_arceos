#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::println;

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    let ret = unsafe { say_hello() };
    println!("C ret {}", ret);
}

#[link(name = "hello", kind = "static")]
unsafe extern "C" {
    fn say_hello() -> i32;
}
