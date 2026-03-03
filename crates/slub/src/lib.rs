//! Linux-like slub allocator algorithms in a unified interface.

#![no_std]

use allocator::{AllocResult, BaseAllocator, ByteAllocator};
use core::alloc::Layout;
use core::ptr::NonNull;

#[cfg(feature = "axerrno")]
use axerrno::AxError;

/// Slub Allocator used by Linux.
pub struct SlubAllocator {
}

impl BaseAllocator for SlubAllocator {
    fn init(&mut self, _start: usize, _size: usize) {
        //
        // mm_core_init_second_part() [mm/mm_init.c]
        //   - set up kernel memory allocators
        //
        unsafe {
            mm_core_init_second_part();
        }
    }
    fn add_memory(&mut self, _start: usize, _size: usize) -> AllocResult {
        unimplemented!("No support for Slub.add_memory()");
    }
}

impl ByteAllocator for SlubAllocator {
    fn alloc(&mut self, layout: Layout) -> AllocResult<NonNull<u8>> {
        let ret = unsafe {
            linux_kmalloc_kernel(layout.size(), layout.align())
        };
        Ok(NonNull::new(ret as *mut _).unwrap())
    }

    fn dealloc(&mut self, _pos: NonNull<u8>, _layout: Layout) {
        unimplemented!("dealloc");
    }

    fn total_bytes(&self) -> usize {
        unimplemented!("");
    }

    fn used_bytes(&self) -> usize {
        unimplemented!("");
    }

    fn available_bytes(&self) -> usize {
        unimplemented!("");
    }
}

impl SlubAllocator {
    pub const fn new() -> Self {
        Self { }
    }
}

unsafe extern "C" {
    fn mm_core_init_second_part();
    fn linux_kmalloc_kernel(size: usize, align: usize) -> usize;
}
