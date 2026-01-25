//! Linux-like memblock allocator algorithms in a unified interface.

#![no_std]

use allocator::{AllocResult, BaseAllocator, ByteAllocator, PageAllocator};
use core::alloc::Layout;
use core::ptr::NonNull;

#[cfg(feature = "axerrno")]
use axerrno::AxError;

/// Early Allocator used by Linux.
pub struct MemblockAllocator<const PAGE_SIZE: usize> {
}

impl<const PAGE_SIZE: usize> BaseAllocator for MemblockAllocator<PAGE_SIZE> {
    fn init(&mut self, start: usize, size: usize) {
        //
        // parse_dtb() [arch/riscv/kernel/setup.c]
        //   - get physical memory range from fdt
        //
        // setup_bootmem() [arch/riscv/mm/init.c]
        //   - reserve areas including kernel, initrd and fdt
        //
        unsafe {
            parse_dtb();
            setup_bootmem();
        }
        unimplemented!("MemblockAllocator.init: {start:#x} {size:#x}");
    }
    fn add_memory(&mut self, start: usize, size: usize) -> AllocResult {
        unimplemented!("No support for Memblock.");
    }
}

impl<const PAGE_SIZE: usize> ByteAllocator for MemblockAllocator<PAGE_SIZE> {
    fn alloc(&mut self, layout: Layout) -> AllocResult<NonNull<u8>> {
        unimplemented!("");
    }

    fn dealloc(&mut self, pos: NonNull<u8>, layout: Layout) {
        unimplemented!("");
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

impl<const PAGE_SIZE: usize> MemblockAllocator<PAGE_SIZE> {
    pub const fn new() -> Self {
        Self { }
    }
}

impl<const PAGE_SIZE: usize> PageAllocator for MemblockAllocator<PAGE_SIZE> {
    const PAGE_SIZE: usize = PAGE_SIZE;

    fn alloc_pages(&mut self, num_pages: usize, align_pow2: usize) -> AllocResult<usize> {
        unimplemented!("");
    }

    fn alloc_pages_at(
        &mut self,
        base: usize,
        num_pages: usize,
        align_pow2: usize,
    ) -> AllocResult<usize> {
        unimplemented!("");
    }

    fn dealloc_pages(&mut self, pos: usize, num_pages: usize) {
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
    fn parse_dtb();
    fn setup_bootmem();
}
