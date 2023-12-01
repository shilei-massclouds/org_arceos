#![cfg_attr(not(test), no_std)]

use axhal::trap::SyscallHandler;
use axhal::arch::TrapFrame;

#[macro_use]
extern crate log;

struct Linux_syscall_handler;

#[crate_interface::impl_interface]
impl SyscallHandler for Linux_syscall_handler {
    fn handle_syscall(tf: &mut TrapFrame) {
        let eid = tf.regs.a7;
        tf.regs.a0 = match eid {
            LINUX_SYSCALL_WRITE => {
                linux_syscall_write(tf)
            },
            LINUX_SYSCALL_WRITEV => {
                linux_syscall_writev(tf)
            },
            LINUX_SYSCALL_READLINKAT => {
                usize::MAX
            },
            LINUX_SYSCALL_FSTATAT => {
                0
            },
            LINUX_SYSCALL_UNAME => {
                linux_syscall_uname(tf)
            },
            LINUX_SYSCALL_BRK => {
                linux_syscall_brk(tf)
            },
            LINUX_SYSCALL_MUNMAP => {
                linux_syscall_munmap(tf)
            },
            LINUX_SYSCALL_MMAP => {
                linux_syscall_mmap(tf)
            },
            LINUX_SYSCALL_EXIT => {
                linux_syscall_exit(tf)
            },
            LINUX_SYSCALL_EXIT_GROUP => {
                linux_syscall_exit_group(tf)
            },
            _ => {
                0
            }
        };
        tf.sepc += 4;
    }
}

//
// Linux syscall
//
const LINUX_SYSCALL_WRITE:      usize = 0x40;
const LINUX_SYSCALL_WRITEV:     usize = 0x42;
const LINUX_SYSCALL_READLINKAT: usize = 0x4e;
const LINUX_SYSCALL_FSTATAT:    usize = 0x4f;
const LINUX_SYSCALL_EXIT:       usize = 0x5d;
const LINUX_SYSCALL_EXIT_GROUP: usize = 0x53;
const LINUX_SYSCALL_UNAME:      usize = 0xa0;
const LINUX_SYSCALL_BRK:        usize = 0xd6;
const LINUX_SYSCALL_MUNMAP:     usize = 0xd7;
const LINUX_SYSCALL_MMAP:       usize = 0xde;


#[derive(Debug)]
#[repr(C)]
struct iovec {
    iov_base: usize,
    iov_len: usize,
}

fn linux_syscall_write(tf: &TrapFrame) -> usize {
    extern crate alloc;
    use alloc::string::String;
    use core::slice;
    debug!("write: {:#x}, {:#x}, {:#x}",
        tf.regs.a0, tf.regs.a1, tf.regs.a2);

    let buf = tf.regs.a1 as *const u8;
    let size = tf.regs.a2;
    let bytes = unsafe { slice::from_raw_parts(buf as *const _, size) };
    /*
    let s = String::from_utf8(bytes.into());
    debug!("{}", s.unwrap());
    */

    axhal::console::write_bytes(bytes);

    return size;
}

fn linux_syscall_writev(tf: &TrapFrame) -> usize {
    extern crate alloc;
    use alloc::string::String;
    use core::slice;

    debug!("writev: {:#x}, {:#x}, {:#x}",
        tf.regs.a0, tf.regs.a1, tf.regs.a2);

    let array = tf.regs.a1 as *const iovec;
    let size = tf.regs.a2;
    let iov_array = unsafe { slice::from_raw_parts(array, size) };
    for iov in iov_array {
        debug!("iov: {:#X} {:#X}", iov.iov_base, iov.iov_len);
        let bytes = unsafe { slice::from_raw_parts(iov.iov_base as *const _, iov.iov_len) };
        let s = String::from_utf8(bytes.into());
        debug!("{}", s.unwrap());
    }

    return size;
}

// void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
fn linux_syscall_mmap(tf: &TrapFrame) -> usize {
    let va = tf.regs.a0;
    let len = tf.regs.a1;
    let prot = tf.regs.a2;
    let flags = tf.regs.a3;
    let fd = tf.regs.a4;
    let off = tf.regs.a5;
    debug!("mmap!!! {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}", va, len, prot, flags, fd, off);

    /*
    if va == 0 {
        return va + 0x1000_0000;
    }
    */

    return va;
}

const UTS_LEN: usize = 64;

#[repr(C)]
struct utsname {
    sysname: [u8; UTS_LEN + 1],
    nodename: [u8; UTS_LEN + 1],
    release: [u8; UTS_LEN + 1],
    version: [u8; UTS_LEN + 1],
    machine: [u8; UTS_LEN + 1],
    domainname: [u8; UTS_LEN + 1],
}

fn linux_syscall_uname(tf: &TrapFrame) -> usize {
    let ptr = tf.regs.a0;
    debug!("uname: {:#x}", ptr);

    let mut uname = unsafe { (ptr as *mut utsname).as_mut().unwrap() };

    init_bytes_from_str(&mut uname.sysname[..], "Linux");
    init_bytes_from_str(&mut uname.nodename[..], "host");
    init_bytes_from_str(&mut uname.domainname[..], "(none)");
    init_bytes_from_str(&mut uname.release[..], "5.9.0-rc4+");
    init_bytes_from_str(&mut uname.version[..], "#1337 SMP Fri Mar 4 09:36:42 CST 2022");
    init_bytes_from_str(&mut uname.machine[..], "riscv64");

    return 0;
}

fn init_bytes_from_str(dst: &mut [u8], src: &str) {
    let src = src.as_bytes();
    let (left, right) = dst.split_at_mut(src.len());
    left.copy_from_slice(src);
    right.fill(0);
}

fn get_brk() -> usize {
    let ptr = (axhal::arch::read_thread_pointer() - 8) as *const usize;
    unsafe { *ptr }
}

fn set_brk(brk: usize) {
    let ptr = (axhal::arch::read_thread_pointer() - 8) as *mut usize;
    unsafe { *ptr = brk; }
}

fn linux_syscall_brk(tf: &TrapFrame) -> usize {
    let va = tf.regs.a0;
    let brk = unsafe { axhal::arch::get_tls_brk() };
    debug!("brk!!! {:#x}, {:#x}", va, brk);
    unsafe {
        if va == 0 {
            brk
        } else {
            unsafe { axhal::arch::set_tls_brk(va) };
            va
        }
    }
}

fn linux_syscall_munmap(tf: &TrapFrame) -> usize {
    let va = tf.regs.a0;
    let len = tf.regs.a1;
    debug!("munmap!!! {:#x} {:#x}", va, len);
    return 0;
}

fn linux_syscall_exit(tf: &TrapFrame) -> usize {
    let ret = tf.regs.a0 as i32;
    debug!("exit ...{}", ret);
    axtask::exit(ret);
    debug!("exit !");
    return 0;
}

fn linux_syscall_exit_group(tf: &TrapFrame) -> usize {
    debug!("exit_group!");
    return 0;
}

pub fn init() {
}
