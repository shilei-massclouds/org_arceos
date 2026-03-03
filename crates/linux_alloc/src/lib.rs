//! Linux-like allocator framework in a unified interface.

#![no_std]

use allocator::{AllocResult, BaseAllocator, ByteAllocator, PageAllocator};
use core::alloc::Layout;
use core::ptr::NonNull;

#[cfg(feature = "axerrno")]
use axerrno::AxError;

use memblock::MemblockAllocator;
use buddy::BuddyAllocator;
use slub::SlubAllocator;

static mut IS_FINAL: bool = false;

/// Early Allocator used by Linux.
pub struct LinuxAllocator<const PAGE_SIZE: usize> {
    early_alloc: MemblockAllocator<PAGE_SIZE>,
    palloc: BuddyAllocator<PAGE_SIZE>,
    balloc: SlubAllocator,
}

impl<const PAGE_SIZE: usize> BaseAllocator for LinuxAllocator<PAGE_SIZE> {
    fn init(&mut self, start: usize, size: usize) {
        self.early_alloc.init(start, size);
    }
    fn add_memory(&mut self, _start: usize, _size: usize) -> AllocResult {
        unimplemented!("No support for Linux.");
    }
}

impl<const PAGE_SIZE: usize> ByteAllocator for LinuxAllocator<PAGE_SIZE> {
    fn alloc(&mut self, layout: Layout) -> AllocResult<NonNull<u8>> {
        if unsafe { IS_FINAL } {
            self.balloc.alloc(layout)
        } else {
            self.early_alloc.alloc(layout)
        }
    }

    fn dealloc(&mut self, pos: NonNull<u8>, layout: Layout) {
        self.early_alloc.dealloc(pos, layout)
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

impl<const PAGE_SIZE: usize> LinuxAllocator<PAGE_SIZE> {
    pub const fn new() -> Self {
        Self {
            early_alloc: MemblockAllocator::new(),
            palloc: BuddyAllocator::new(),
            balloc: SlubAllocator::new(),
        }
    }
    pub fn finalize(&mut self) {
        // Safety: this function can only be called at boot-time.
        // At that time, there's only one task.
        #[cfg(not(feature = "only-early"))]
        unsafe {
            assert!(!IS_FINAL);
            IS_FINAL = true;
            self.palloc.init(0, 0);
            self.balloc.init(0, 0);
        }
    }
}

impl<const PAGE_SIZE: usize> PageAllocator for LinuxAllocator<PAGE_SIZE> {
    const PAGE_SIZE: usize = PAGE_SIZE;

    fn alloc_pages(&mut self, num_pages: usize, align_pow2: usize) -> AllocResult<usize> {
        if unsafe { IS_FINAL } {
            panic!("No buddy system.");
        } else {
            self.early_alloc.alloc_pages(num_pages, align_pow2)
        }
    }

    fn alloc_pages_at(
        &mut self,
        _base: usize,
        _num_pages: usize,
        _align_pow2: usize,
    ) -> AllocResult<usize> {
        unimplemented!("LinuxAllocator::alloc_pages_at");
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
