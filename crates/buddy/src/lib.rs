//! Linux-like buddy allocator algorithms in a unified interface.

#![no_std]

use allocator::{AllocResult, BaseAllocator, PageAllocator};
#[cfg(feature = "axerrno")]
use axerrno::AxError;
use linux_adaptor::LinuxAdaptorState;

/// Buddy Allocator used by Linux.
pub struct BuddyAllocator<const PAGE_SIZE: usize> {
}

impl<const PAGE_SIZE: usize> BaseAllocator for BuddyAllocator<PAGE_SIZE> {
    fn init(&mut self, _start: usize, _size: usize) {
        linux_adaptor::advance_to(LinuxAdaptorState::SetupBuddy);
    }
    fn add_memory(&mut self, _start: usize, _size: usize) -> AllocResult {
        unimplemented!("No support for Buddy.add_memory()");
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
