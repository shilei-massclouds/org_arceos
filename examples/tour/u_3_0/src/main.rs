#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;

use core::{mem, str};

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    // Makesure that we can access pflash region.
    unsafe {
        let magic = 0x1234;
        println!("Got pflash magic: {}", magic);
    }
}
