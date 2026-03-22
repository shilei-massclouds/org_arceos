#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

extern crate alloc;

#[cfg(feature = "axstd")]
use axstd::println;

use alloc::vec;
use axstd::fs::File;
use axstd::io::{Read, Write, Seek, SeekFrom};

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    println!("Hello, Linux Block Driver!");
    test_block();
    println!("Linux Block Driver: test OK!");
}

const BUF_SIZE: usize = 1024;

/* The initial magic of 'disk.img' created by ArceOS */
const INIT_MAGIC: usize = 0x2e73666b6d9058eb;
const TEST_MAGIC: usize = 0xa00afeedb00bfeed;

fn test_block() {
    let fname = "/dev/vda";
    let mut file = File::options()
        .read(true)
        .write(true)
        .open(fname).unwrap();

    let metadata = file.metadata().unwrap();
    println!("{:?} '{}': {} bytes (occupy {} blocks)",
        metadata.file_type(), fname,
        metadata.size(), metadata.blocks());

    /* Check the header magic of 'disk.img' */
    let mut buf = vec![0; BUF_SIZE];
    let _ = file.seek(SeekFrom::Start(0));
    let n = file.read(&mut buf).unwrap();
    assert_eq!(n, BUF_SIZE);
    assert_eq!(&buf[..8], INIT_MAGIC.to_ne_bytes(),
        "verify the init magic err.");

    /* Overwrite the magic */
    buf[..8].copy_from_slice(&TEST_MAGIC.to_ne_bytes());
    let _ = file.seek(SeekFrom::Start(0));
    file.write_all(&buf).unwrap();

    /* Check the new magic */
    buf.fill(0);
    let _ = file.seek(SeekFrom::Start(0));
    let n = file.read(&mut buf).unwrap();
    assert_eq!(n, BUF_SIZE);
    assert_eq!(&buf[..8], TEST_MAGIC.to_ne_bytes(), "verify the new magic err.");

    /* Restore the old magic */
    buf[..8].copy_from_slice(&INIT_MAGIC.to_ne_bytes());
    let _ = file.seek(SeekFrom::Start(0));
    file.write_all(&buf).unwrap();

    /* Makesure everything is fine */
    buf.fill(0);
    let _ = file.seek(SeekFrom::Start(0));
    let n = file.read(&mut buf).unwrap();
    assert_eq!(n, BUF_SIZE);
    assert_eq!(&buf[..8], INIT_MAGIC.to_ne_bytes(), "verify the init magic (recovered) err.");
}
