use std::fs::{self, File, FileType};
use std::io::{self, prelude::*};
use std::{string::String, vec::Vec};

#[cfg(all(not(feature = "axstd"), unix))]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

use crate::path_to_str;

macro_rules! print_err {
    ($cmd: literal, $msg: expr) => {
        println!("{}: {}", $cmd, $msg);
    };
    ($cmd: literal, $arg: expr, $err: expr) => {
        println!("{}: {}: {}", $cmd, $arg, $err);
    };
}

fn file_type_to_char(ty: FileType) -> char {
    if ty.is_char_device() {
        'c'
    } else if ty.is_block_device() {
        'b'
    } else if ty.is_socket() {
        's'
    } else if ty.is_fifo() {
        'p'
    } else if ty.is_symlink() {
        'l'
    } else if ty.is_dir() {
        'd'
    } else if ty.is_file() {
        '-'
    } else {
        '?'
    }
}

#[rustfmt::skip]
const fn file_perm_to_rwx(mode: u32) -> [u8; 9] {
    let mut perm = [b'-'; 9];
    macro_rules! set {
        ($bit:literal, $rwx:literal) => {
            if mode & (1 << $bit) != 0 {
                perm[8 - $bit] = $rwx
            }
        };
    }

    set!(2, b'r'); set!(1, b'w'); set!(0, b'x');
    set!(5, b'r'); set!(4, b'w'); set!(3, b'x');
    set!(8, b'r'); set!(7, b'w'); set!(6, b'x');
    perm
}

pub fn create_file(path: &str) -> File {
    let f = File::create(path).unwrap();
    let metadata = f.metadata().unwrap();
    assert!(metadata.is_file());
    println!("Create '{}' ok!", path);
    f
}

pub fn open_file(path: &str) -> File {
    let f = File::open(path).unwrap();
    let metadata = f.metadata().unwrap();
    assert!(metadata.is_file());
    println!("Open '{}' ok! size {}.", path, metadata.size());
    f
}

pub fn show_dir(args: &str) {
    println!("Show directory '{}'", args);
    let current_dir = std::env::current_dir().unwrap();
    let args = if args.is_empty() {
        path_to_str(&current_dir)
    } else {
        args
    };
    let name_count = args.split_whitespace().count();

    fn show_entry_info(path: &str, entry: &str) -> io::Result<()> {
        let metadata = fs::metadata(path)?;
        let size = metadata.len();
        let file_type = metadata.file_type();
        let file_type_char = file_type_to_char(file_type);
        let rwx = file_perm_to_rwx(metadata.permissions().mode());
        let rwx = unsafe { core::str::from_utf8_unchecked(&rwx) };
        println!("{}{} {:>8} {}", file_type_char, rwx, size, entry);
        Ok(())
    }

    fn list_one(name: &str, print_name: bool) -> io::Result<()> {
        let is_dir = fs::metadata(name)?.is_dir();
        if !is_dir {
            return show_entry_info(name, name);
        }

        if print_name {
            println!("{}:", name);
        }
        let mut entries = fs::read_dir(name)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect::<Vec<_>>();
        entries.sort();

        for entry in entries {
            let entry = path_to_str(&entry);
            let path = String::from(name) + "/" + entry;
            if let Err(e) = show_entry_info(&path, entry) {
                print_err!("ls", path, e);
            }
        }
        Ok(())
    }

    for (i, name) in args.split_whitespace().enumerate() {
        if i > 0 {
            println!();
        }
        if let Err(e) = list_one(name, name_count > 1) {
            print_err!("ls", name, e);
        }
    }
}

pub fn write_file(f: &mut File, buf: &[u8]) -> usize {
    let old_size = f.metadata().unwrap().size();
    f.write_all(buf).unwrap();
    let new_size = f.metadata().unwrap().size();
    assert_eq!(new_size - old_size, buf.len() as u64);
    buf.len()
}

pub fn read_file(f: &mut File, buf: &mut [u8]) -> usize {
    let size = f.metadata().unwrap().size() as usize;
    assert_eq!(size, buf.len());
    f.read_exact(buf).unwrap();
    size
}

pub fn remove_file(path: &str) {
    fs::remove_file(path).unwrap();
}

pub fn create_dir(path: &str) {
    mkdir(path);
    let metadata = fs::metadata(path).unwrap();
    assert!(metadata.is_dir());
}

fn mkdir(args: &str) {
    if args.is_empty() {
        print_err!("mkdir", "missing operand");
        return;
    }

    fn mkdir_one(path: &str) -> io::Result<()> {
        fs::create_dir(path)
    }

    for path in args.split_whitespace() {
        if let Err(e) = mkdir_one(path) {
            print_err!("mkdir", format_args!("cannot create directory '{path}'"), e);
        }
    }
}

pub fn remove_dir(path: &str) {
    fs::remove_dir(path).unwrap();
}
