//! Linux-like buddy allocator algorithms in a unified interface.

#![no_std]

use allocator::{AllocResult, BaseAllocator, ByteAllocator, PageAllocator};
use core::alloc::Layout;
use core::ptr::NonNull;

#[cfg(feature = "axerrno")]
use axerrno::AxError;

/// Buddy Allocator used by Linux.
pub struct BuddyAllocator<const PAGE_SIZE: usize> {
}

impl<const PAGE_SIZE: usize> BaseAllocator for BuddyAllocator<PAGE_SIZE> {
    fn init(&mut self, _start: usize, _size: usize) {
        //
        // misc_mem_init() [arch/riscv/mm/init.c]
        //   - prepare node/zone/mem_map for buddy system
        //
        // mm_core_init() [mm/mm_init.c]
        //   - set up kernel memory allocators
        unsafe {
            misc_mem_init();
            mm_core_init();
        }
    }
    fn add_memory(&mut self, _start: usize, _size: usize) -> AllocResult {
        unimplemented!("No support for Buddy.add_memory()");
    }
}

impl<const PAGE_SIZE: usize> ByteAllocator for BuddyAllocator<PAGE_SIZE> {
    fn alloc(&mut self, _layout: Layout) -> AllocResult<NonNull<u8>> {
        unimplemented!("alloc");
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

impl<const PAGE_SIZE: usize> BuddyAllocator<PAGE_SIZE> {
    pub const fn new() -> Self {
        Self { }
    }
}

impl<const PAGE_SIZE: usize> PageAllocator for BuddyAllocator<PAGE_SIZE> {
    const PAGE_SIZE: usize = PAGE_SIZE;

    fn alloc_pages(&mut self, _num_pages: usize, _align_pow2: usize) -> AllocResult<usize> {
        unimplemented!("alloc_pages");
    }

    fn alloc_pages_at(
        &mut self,
        _base: usize,
        _num_pages: usize,
        _align_pow2: usize,
    ) -> AllocResult<usize> {
        unimplemented!("");
    }

    fn dealloc_pages(&mut self, _pos: usize, _num_pages: usize) {
        unimplemented!("");
    }

    fn total_pages(&self) -> usize {
        unimplemented!("");
    }

    fn used_pages(&self) -> usize {
        unimplemented!("");
    }

    fn available_pages(&self) -> usize {
        unimplemented!("");
    }
}

unsafe extern "C" {
    fn misc_mem_init();
    fn mm_core_init();
}
