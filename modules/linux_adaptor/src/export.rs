//! All exported symbols from ArceOS.

use core::ffi::{c_char, CStr};
use alloc::alloc::{alloc, Layout};
use axalloc::global_allocator;
use axconfig::plat::PHYS_VIRT_OFFSET;
use axhal::mem::PAGE_SIZE_4K;

/// Offset between VirtAddr and PhysAddr in kernel aspace.
#[unsafe(no_mangle)]
static va_pa_offset: usize = PHYS_VIRT_OFFSET;

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
static physvirt_offset: isize = -(PHYS_VIRT_OFFSET as isize);

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

/// Stuff needed by irq-sifive-plic
#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
static boot_cpu_hartid: u64 = 0;

/// the offset between the kernel virtual and physical mappings
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
static kimage_voffset: u64 = 0;

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
static vabits_actual: u64 = 48;

// NOTE: fix nr_cpu_ids according to real kernel config.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
static nr_cpu_ids: u32 = 1;

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
static xen_domain_type: u32 = 0;

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
static __boot_cpu_mode: u32 = 0;

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
static arm64_use_ng_mappings: bool = false;
