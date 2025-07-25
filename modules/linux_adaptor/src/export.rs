//! All exported symbols from ArceOS.

use core::ffi::{c_char, CStr};
use alloc::alloc::{alloc, Layout};
use axalloc::global_allocator;
use axconfig::plat::PHYS_VIRT_OFFSET;
use axhal::mem::PAGE_SIZE_4K;

/// Offset between VirtAddr and PhysAddr in kernel aspace.
#[unsafe(no_mangle)]
static va_pa_offset: usize = PHYS_VIRT_OFFSET;

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

/// Printk
#[unsafe(no_mangle)]
pub extern "C" fn cl_printk(ptr: *const c_char) {
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let rust_str = c_str.to_str().expect("Bad encoding");
    ax_print!("{}", rust_str);
}

/// Terminate
#[unsafe(no_mangle)]
pub extern "C" fn cl_terminate() {
    axhal::misc::terminate()
}

/// Debug log.
#[unsafe(no_mangle)]
pub extern "C" fn cl_log_debug(ptr: *const c_char) {
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let rust_str = c_str.to_str().expect("Bad encoding");
    debug!("{}", rust_str);
}

/// Error log.
#[unsafe(no_mangle)]
pub extern "C" fn cl_log_error(ptr: *const c_char) {
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let rust_str = c_str.to_str().expect("Bad encoding");
    error!("{}", rust_str);
}

type LinuxKthreadFunc = extern fn(usize) -> isize;

/// Spawn a task(kthread).
#[unsafe(no_mangle)]
pub extern "C" fn cl_kthread_run(
    task_ptr: u64, threadfn: LinuxKthreadFunc, arg: usize
) -> u64 {
    let task = axtask::spawn_raw(
        move || {
            error!("linux kthread: fn {:#?} {:#x}", threadfn, arg);
            threadfn(arg);
        },
        "linux kthread".into(),
        0x1000,
    );
    error!("Kthread task pointer({:#x})", task_ptr);
    task.set_private(task_ptr);
    task.id().as_u64()
}

/// Reschedule.
#[unsafe(no_mangle)]
pub extern "C" fn cl_resched(back_to_runq: usize) {
    if back_to_runq != 0 {
        axtask::yield_now();
    } else {
        axtask::__resched();
    }
}

/// Reschedule.
#[unsafe(no_mangle)]
pub extern "C" fn cl_wake_up(tid: u64) {
    error!("wake up thread: {}", tid);
    axtask::__wake_up(tid)
}
