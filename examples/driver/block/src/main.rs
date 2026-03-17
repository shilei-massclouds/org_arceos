#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::println;

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    println!("Hello, Linux Block Driver!");
    test_block();
    println!("Linux Block Driver: test OK!");
}

fn test_block() {
    unsafe {
        cl_test_block();
    }
}

unsafe extern "C" {
    fn cl_test_block();
}
