#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::{println, thread};

extern crate alloc;
use alloc::string::String;

const PFLASH_START: usize = 0xffff_ffc0_2200_0000;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    let mut pos = PFLASH_START;
    let app_num = parse_literal_hex(pos);
    assert_eq!(app_num, 2);
    pos += 8;

    let size = parse_literal_hex(pos);
    println!("app size: {}", size);
    pos += 8;

    let code = unsafe {
        core::slice::from_raw_parts(pos as *const u8, size)
    };
    pos += size;
    println!("app pos: {:#X}", pos);

    thread::spawn(move || {
        let (entry, end) = parse_elf(code);
        println!("elf entry: {:#X}", entry);

        println!("App {:?}", thread::current().id());
        run_app(entry, end);
    });

    loop {
        thread::yield_now();
    }
}

// Note: Length of literal hex must be 8.
fn parse_literal_hex(pos: usize) -> usize {
    let hex = unsafe { core::slice::from_raw_parts(pos as *const u8, 8) };
    let hex = String::from_utf8(hex.into()).expect("bad hex number.");
    usize::from_str_radix(&hex, 16).expect("NOT hex number.")
}

fn parse_elf(_code: &[u8]) -> (usize, usize) {
    unimplemented!("parse_elf");
}

fn run_app(_entry: usize, _end: usize) {
    unimplemented!("run_app");
}
