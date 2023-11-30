#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::println;

extern crate alloc;
use alloc::string::String;

const PFLASH_START: usize = 0xffff_ffc0_2200_0000;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    let app_num = parse_literal_hex(PFLASH_START);
    assert_eq!(app_num, 2);

    println!("Hello, world!");
}

// Note: Length of literal hex must be 8.
fn parse_literal_hex(pos: usize) -> usize {
    let hex = unsafe { core::slice::from_raw_parts(pos as *const u8, 8) };
    let hex = String::from_utf8(hex.into()).expect("bad hex number.");
    usize::from_str_radix(&hex, 16).expect("NOT hex number.")
}
