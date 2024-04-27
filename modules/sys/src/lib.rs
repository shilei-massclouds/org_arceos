#![cfg_attr(not(test), no_std)]

use taskctx::Tid;
use axconfig::TASK_STACK_SIZE;

#[macro_use]
extern crate log;

#[cfg(target_arch = "x86_64")]
const ARCH_SET_FS: usize = 0x1002;

const RLIMIT_STACK: usize = 3; /* max stack size */
//const RLIM_NLIMITS: usize = 16;

#[allow(dead_code)]
struct RLimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

impl RLimit64 {
    pub fn new(rlim_cur: u64, rlim_max: u64) -> Self {
        Self { rlim_cur, rlim_max }
    }
}

pub fn gettid() -> usize {
    taskctx::current_ctx().tid()
}

pub fn getpid() -> usize {
    taskctx::current_ctx().tgid()
}

pub fn getgid() -> usize {
    warn!("impl getgid");
    0
}

pub fn prlimit64(tid: Tid, resource: usize, new_rlim: usize, old_rlim: usize) -> usize {
    warn!(
        "linux_syscall_prlimit64: tid {}, resource: {}, {:?} {:?}",
        tid, resource, new_rlim, old_rlim
    );

    assert!(tid == 0);

    let old_rlim = old_rlim as *mut RLimit64;

    match resource {
        RLIMIT_STACK => {
            let stack_size = TASK_STACK_SIZE as u64;
            unsafe {
                *old_rlim = RLimit64::new(stack_size, stack_size);
            }
            0
        }
        _ => {
            unimplemented!("Resource Type: {}", resource);
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub fn arch_prctl(code: usize, addr: usize) -> usize {
    let ctx = taskctx::current_ctx();
    match code {
        ARCH_SET_FS => {
            use axhal::arch::write_thread_pointer;
            warn!("=========== arch_prctl ARCH_SET_FS {:#X}", addr);
            unsafe {
                write_thread_pointer(addr);
                (*ctx.ctx_mut_ptr()).fs_base = addr;
            }
            0
        },
        _ =>  {
            error!("=========== arch_prctl code {:#X}", code);
            axerrno::LinuxError::EPERM.code() as usize
        }
    }
}
