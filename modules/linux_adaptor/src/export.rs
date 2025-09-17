//! All exported symbols from ArceOS.

use core::ffi::{c_char, CStr};
use alloc::alloc::{alloc, Layout};
use axalloc::global_allocator;
use axhal::mem::PAGE_SIZE_4K;
use axhal::mem::MemRegionFlags;
use memory_addr::{align_down_4k, is_aligned_4k};
use axtask::current;
use crate::kallsyms::get_ksym;

const CL_TASK_STATE_MASK:   usize = 0x00000003;

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

    axtask::yield_now()
}

/// Reschedule.
#[unsafe(no_mangle)]
pub extern "C" fn cl_get_ksym(addr: usize, s: *mut u8, size: usize) {
    let name = get_ksym(addr).unwrap_or("[unknown]");
    unsafe {
        let dst = core::slice::from_raw_parts_mut(s, size);
        dst[..name.len()].copy_from_slice(name.as_bytes());
    }
}

unsafe extern "C" {
    static cl_fixaddr_start: usize;
}

/// Set fixmap.
#[unsafe(no_mangle)]
pub extern "C" fn cl_set_fixmap(idx: usize, phys: usize, prot: usize) -> usize {
    let fixaddr_start = unsafe { cl_fixaddr_start };
    let va = fixaddr_start - PAGE_SIZE_4K * idx;
    error!("FIXADDR_START: {:#x}; va: {:#x}", fixaddr_start, va);

    let aspace = axmm::kernel_aspace();
    if prot == 0 {
        // Clear fixmap.
        aspace.lock()
            .unmap(va.into(), PAGE_SIZE_4K)
            .unwrap_or_else(|e| {
                panic!("unmap fixmap area {va:#x} error: {}", e)
            });
        return 0;
    }

    let flags = MemRegionFlags::RESERVED | MemRegionFlags::READ | MemRegionFlags::WRITE | MemRegionFlags::EXECUTE;

    aspace.lock()
        .map_linear(va.into(), align_down_4k(phys).into(), PAGE_SIZE_4K, flags.into())
        .unwrap_or_else(|e| {
            panic!("bad fixmap {va:#x} -> {phys:#x}({prot:?}): {}", e)
        });

    error!("idx({:#x}) phys({:#x}) prot({:#x})", idx, phys, prot);
    va + (phys & (PAGE_SIZE_4K - 1))
}

const _PAGE_READ : usize = 1 << 1;
const _PAGE_WRITE: usize = 1 << 2;
const _PAGE_EXEC : usize = 1 << 3;

/// VMalloc range linear-map
#[unsafe(no_mangle)]
pub extern "C" fn cl_vmap_range(va: usize, pa: usize, size: usize, prot: usize) -> usize {
    assert!(is_aligned_4k(va));
    assert!(is_aligned_4k(pa));
    assert!(is_aligned_4k(size));

    let mut flags: MemRegionFlags = MemRegionFlags::RESERVED;
    if (prot & _PAGE_READ) != 0 {
        flags |= MemRegionFlags::READ;
    }
    if (prot & _PAGE_WRITE) != 0 {
        flags |= MemRegionFlags::WRITE;
    }
    if (prot & _PAGE_EXEC) != 0 {
        flags |= MemRegionFlags::EXECUTE;
    }

    let aspace = axmm::kernel_aspace();
    aspace.lock()
        .map_linear(va.into(), pa.into(), size, flags.into())
        .unwrap_or_else(|e| {
            panic!("bad fixmap {va:#x} -> {pa:#x}({prot:#x}): {}", e)
        });
    0
}
