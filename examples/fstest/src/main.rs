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
    remove_file, create_dir, remove_dir, check_dir, check_file,
};

#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    println!("fstest ..");

    if !check_dir("tmp") {
        panic!("No tmp directory.");
    }

    // Check dir which has been created last time.
    if !check_dir("dir2") {
        println!("No 'dir2' found which has been created last time.");
    }

    if !check_file("last_file") {
        println!("No 'last_file' found which has been created last time.");
    }

    // List all at root directory.
    show_dir("");

    // Create and write sth into a file at root direcotry.
    do_file_test("f1.txt");

    // Create a directory.
    create_dir("dir1");

    do_file_test("dir1/f2.txt");

    // Remove the directory.
    remove_dir("dir1");

    // Create an extra directory.
    create_dir("dir2");

    if !check_dir("dir2") {
        panic!("No 'dir2' found.");
    }

    create_file("last_file");
    if !check_file("last_file") {
        panic!("No 'last_file' found.");
    }

    // NOTE: move it in clinux kthread.
    unsafe {
        cl_wakeup_flusher_threads();
    }

    println!("wait for one second ..");
    // Let's fly for a while and jbd2 may write journal.
    std::thread::sleep(std::time::Duration::new(1, 0));

    println!("fstest ok!");
}

unsafe extern "C" {
    fn cl_wakeup_flusher_threads();
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
    println!("Remove '{}' ...", path);
    remove_file(path);
    println!("Remove '{}' ok!", path);
}
