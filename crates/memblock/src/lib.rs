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
    fn init(&mut self, _start: usize, _size: usize) {
        //
        // parse_dtb() [arch/riscv/kernel/setup.c]
        //   - get physical memory range from fdt
        //
        // sbi_init() [arch/riscv/kernel/setup.c]
        //
        // setup_bootmem() [arch/riscv/mm/init.c]
        //   - reserve areas including kernel, initrd and fdt
        //
        unsafe {
            parse_dtb();
            sbi_init();
            setup_bootmem();
        }
    }
    fn add_memory(&mut self, _start: usize, _size: usize) -> AllocResult {
        unimplemented!("No support for Memblock.");
    }
}

impl<const PAGE_SIZE: usize> ByteAllocator for MemblockAllocator<PAGE_SIZE> {
    fn alloc(&mut self, layout: Layout) -> AllocResult<NonNull<u8>> {
        let va = unsafe {
            linux_memblock_alloc(layout.size(), layout.align())
        };
        Ok(NonNull::new(va as *mut u8).unwrap())
    }

    fn dealloc(&mut self, pos: NonNull<u8>, layout: Layout) {
        unsafe {
            memblock_free(pos.as_ptr() as usize, layout.size());
        }
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
        let va = unsafe {
            linux_memblock_alloc(num_pages * PAGE_SIZE, align_pow2)
        };
        Ok(va)
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
    fn parse_dtb();
    fn sbi_init();
    fn setup_bootmem();
    fn linux_memblock_alloc(size: usize, align: usize) -> usize;
    fn memblock_free(ptr: usize, size: usize);
}
