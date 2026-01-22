#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;

use core::{mem, str};
use std::thread;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    println!("Multi-task is starting ...");

    let worker = thread::spawn(move || {
        println!("Spawned-thread ...");
        0
    });

    let ret = worker.join();
    // Makesure that worker has finished its work.
    assert_eq!(ret, Ok(0));

    println!("Multi-task OK!");
}
