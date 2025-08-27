//! All exported symbols from ArceOS.

use core::ffi::{c_char, CStr};
use alloc::alloc::{alloc, Layout};
use axalloc::global_allocator;
use axhal::mem::PAGE_SIZE_4K;
use axtask::current;

const CL_TASK_STATE_MASK:   usize = 0x00000003;

const TASK_RUNNING:         usize = 0x00000000;
const TASK_INTERRUPTIBLE:   usize = 0x00000001;
const TASK_UNINTERRUPTIBLE: usize = 0x00000002;

/// Alloc bytes.
#[unsafe(no_mangle)]
pub extern "C" fn cl_rust_alloc(size: usize, align: usize) -> usize {
    let layout = Layout::from_size_align(size, align).unwrap();
    let ptr = unsafe { alloc(layout) };
    ptr as usize
}

/// Dealloc bytes.
#[unsafe(no_mangle)]
pub extern "C" fn cl_rust_dealloc(addr: usize) {
    info!("No impl. We don't know layout for addr '{:#x}'.", addr);
}

/// Alloc pages.
#[unsafe(no_mangle)]
pub extern "C" fn cl_alloc_pages(size: usize, align: usize) -> usize {
    assert!(size > 0);
    assert_eq!(size % PAGE_SIZE_4K, 0);
    assert!(align > 0);
    assert_eq!(align % PAGE_SIZE_4K, 0);
    let count = size >> 12;
    global_allocator().alloc_pages(count, align).unwrap()
}

/// Free pages.
#[unsafe(no_mangle)]
pub extern "C" fn cl_free_pages(addr: usize, count: usize) {
    assert!(addr > 0);
    assert!(count > 0);
    global_allocator().dealloc_pages(addr, count)
}

/// Printk
#[unsafe(no_mangle)]
pub extern "C" fn cl_printk(level: u8, ptr: *const c_char) {
    /* Note: 'error!' can destroy current int linux. WHY? */
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let rust_str = c_str.to_str().expect("Bad encoding");
    match level as char {
        '7' => debug!("{}", rust_str),
        '6' => info!("{}", rust_str),
        '5' => (),  // Notice Level: indicate dummy linux functions.
        '4' => warn!("{}", rust_str),
        '3' => error!("{}", rust_str),
        _ => ax_print!("{}", rust_str),
    }
}

/// Terminate
#[unsafe(no_mangle)]
pub extern "C" fn cl_terminate() {
    axhal::misc::terminate()
}

type LinuxKthreadFunc = extern fn(usize) -> isize;

/// Spawn a task(kthread).
#[unsafe(no_mangle)]
pub extern "C" fn cl_kthread_run(
    task_ptr: u64, threadfn: LinuxKthreadFunc, arg: usize
) -> u64 {
    let task = axtask::spawn_raw(
        move || {
            debug!("linux kthread: fn {:#?} {:#x}", threadfn, arg);
            threadfn(arg);
        },
        "linux kthread".into(),
        0x2000,     // KThread stack size must be compatible with linux.
    );
    debug!("Kthread task pointer({:#x})", task_ptr);
    task.set_private(task_ptr);
    task.id().as_u64()
}

/// Reschedule.
#[unsafe(no_mangle)]
pub extern "C" fn cl_resched(state: usize) {
    debug!("resched current .. state {}(origin:{}); curr {}",
        state & CL_TASK_STATE_MASK, state, current().id_name());

    match state & CL_TASK_STATE_MASK {
        TASK_RUNNING => axtask::yield_now(),
        TASK_INTERRUPTIBLE => axtask::__resched(true),
        TASK_UNINTERRUPTIBLE => axtask::__resched(false),
        _ => panic!("bad task state: {}", state),
    }
}

/// Reschedule.
#[unsafe(no_mangle)]
pub extern "C" fn cl_wake_up(tid: u64) {
    debug!("wake up thread: {}", tid);
    axtask::__wake_up(tid)
}
