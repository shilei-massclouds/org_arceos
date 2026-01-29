#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;

mod bf;
use bf::do_test;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    do_test();
}
