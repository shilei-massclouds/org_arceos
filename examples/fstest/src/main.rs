#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;

#[cfg(not(feature = "axstd"))]
fn path_to_str(path: &impl AsRef<std::ffi::OsStr>) -> &str {
    path.as_ref().to_str().unwrap()
}

#[cfg(feature = "axstd")]
fn path_to_str(path: &str) -> &str {
    path
}

mod cmd;

use cmd::{
    show_dir, create_file, open_file, write_file, read_file,
    remove_file, create_dir, remove_dir
};

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    println!("fstest ..");

    // List all at root directory.
    show_dir("");

    // Create and write sth into a file at root direcotry.
    do_file_test("f1.txt");

    // Create a directory.
    create_dir("dir1");

    do_file_test("dir1/f2.txt");

    // Remove the directory.
    remove_dir("dir1");

    println!("fstest ok!");
}

fn do_file_test(path: &str) {
    let mut f1 = create_file(path);

    const BUF1_SIZE: usize = 350;
    const BUF2_SIZE: usize = 250;
    let buf1 = [0xA1; BUF1_SIZE];
    let buf2 = [0xB1; BUF2_SIZE];

    let ret = write_file(&mut f1, &buf1);
    assert_eq!(ret, buf1.len());
    let ret = write_file(&mut f1, &buf2);
    assert_eq!(ret, buf2.len());
    drop(f1);
    println!("Write '{}' ok!", path);

    // Reopen the file and verify its content.
    let mut rbuf = [0x0; BUF1_SIZE+BUF2_SIZE];
    let mut f1 = open_file(path);
    let ret = read_file(&mut f1, &mut rbuf);
    assert_eq!(ret, rbuf.len());
    assert_eq!(rbuf[0], 0xA1);
    assert_eq!(rbuf[BUF1_SIZE - 1], 0xA1);
    assert_eq!(rbuf[BUF1_SIZE], 0xB1);
    assert_eq!(rbuf[rbuf.len() - 1], 0xB1);
    println!("Read and verify '{}' ok!", path);

    // Remove the file.
    remove_file(path);
    println!("Remove '{}' ok!", path);
}
