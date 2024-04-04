#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate log;

extern crate alloc;
use alloc::sync::Arc;
use alloc::string::String;

use axerrno::LinuxError;
use axfile::fops::File;
use axfile::fops::OpenOptions;
use spinlock::SpinNoIrq;
use mutex::AxMutex;
use mutex_helper::MutexHelper;

pub fn openat(_dtd: usize, filename: &str, _flags: usize, _mode: usize) -> usize {
    let mut opts = OpenOptions::new();
    opts.read(true);

    let current = task::current();
    let fs = current.fs.lock();
    let file = match File::open(&filename, &opts, &fs) {
        Ok(f) => f,
        Err(e) => {
            return (-LinuxError::from(e).code()) as usize;
        },
    };
    let fd = current.filetable.lock().insert(Arc::new(AxMutex::new(file)));
    error!("openat fd {}", fd);
    fd
}

pub fn read(fd: usize, ubuf: &mut [u8]) -> usize {
    let count = ubuf.len();
    let current = task::current();
    let file = current.filetable.lock().get_file(fd).unwrap();
    let mut pos = 0;
    assert!(count < 1024);
    let mut kbuf: [u8; 1024] = [0; 1024];
    while pos < count {
        let helper = MutexHelper::new();
        let ret = file.lock(helper).read(&mut kbuf[pos..]).unwrap();
        if ret == 0 {
            break;
        }
        pos += ret;
    }

    axhal::arch::enable_sum();
    ubuf.copy_from_slice(&kbuf[..count]);
    axhal::arch::disable_sum();
    //error!("linux_syscall_read: fd {}, buf {:#X}, count {}, ret {}", fd, buf, count, pos);
    pos
}

pub fn write(ubuf: &[u8]) -> usize {
    axhal::arch::enable_sum();
    axhal::console::write_bytes(ubuf);
    axhal::arch::disable_sum();
    ubuf.len()
}

#[derive(Debug)]
#[repr(C)]
pub struct iovec {
    iov_base: usize,
    iov_len: usize,
}

pub fn writev(iov_array: &[iovec]) -> usize {
    axhal::arch::enable_sum();
    for iov in iov_array {
        debug!("iov: {:#X} {:#X}", iov.iov_base, iov.iov_len);
        let bytes = unsafe { core::slice::from_raw_parts(iov.iov_base as *const _, iov.iov_len) };
        let s = String::from_utf8(bytes.into());
        error!("{}", s.unwrap());
    }
    axhal::arch::disable_sum();
    iov_array.len()
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct KernelStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub _pad0: u64,
    pub st_size: u64,
    pub st_blksize: u32,
    pub _pad1: u32,
    pub st_blocks: u64,
    pub st_atime_sec: isize,
    pub st_atime_nsec: isize,
    pub st_mtime_sec: isize,
    pub st_mtime_nsec: isize,
    pub st_ctime_sec: isize,
    pub st_ctime_nsec: isize,
}

pub fn fstatat(dirfd: usize, _path: &str, statbuf_ptr: usize, _flags: usize) -> usize {
    let current = task::current();
    let filetable = current.filetable.lock();
    let file = match filetable.get_file(dirfd) {
        Some(f) => f,
        None => {
            return (-2isize) as usize;
        },
    };
    let helper = MutexHelper::new();
    let metadata = file.lock(helper).get_attr().unwrap();
    let ty = metadata.file_type() as u8;
    let perm = metadata.perm().bits() as u32;
    let st_mode = ((ty as u32) << 12) | perm;
    let st_size = metadata.size();
    error!("st_size: {}", st_size);

    let statbuf = statbuf_ptr as *mut KernelStat;
    axhal::arch::enable_sum();
    unsafe {
        *statbuf = KernelStat {
            st_ino: 1,
            st_nlink: 1,
            st_mode,
            st_uid: 1000,
            st_gid: 1000,
            st_size: st_size,
            st_blocks: metadata.blocks() as _,
            st_blksize: 512,
            ..Default::default()
        };
    }
    axhal::arch::disable_sum();
    0
}
