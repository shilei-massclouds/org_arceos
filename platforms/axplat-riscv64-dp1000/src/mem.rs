use axplat::mem::{MemIf, PhysAddr, RawRange, VirtAddr, pa, va};

struct MemIfImpl;

#[impl_plat_interface]
impl MemIf for MemIfImpl {
    /// Returns all physical memory (RAM) ranges on the platform.
    ///
    /// All memory ranges except reserved ranges (including the kernel loaded
    /// range) are free for allocation.
    fn phys_ram_ranges() -> &'static [RawRange] {
        // FixMe: return ranges from fdt.
        &[]
    }

    /// Returns all reserved physical memory ranges on the platform.
    ///
    /// Reserved memory can be contained in [`phys_ram_ranges`], they are not
    /// allocatable but should be mapped to kernel's address space.
    ///
    /// Note that the ranges returned should not include the range where the
    /// kernel is loaded.
    fn reserved_phys_ram_ranges() -> &'static [RawRange] {
        // FixMe: return ranges from fdt.
        &[]
    }

    /// Returns all device memory (MMIO) ranges on the platform.
    fn mmio_ranges() -> &'static [RawRange] {
        // FixMe: return ranges from fdt.
        &[]
    }

    /// Translates a physical address to a virtual address.
    ///
    /// It is just an easy way to access physical memory when virtual memory
    /// is enabled. The mapping may not be unique, there can be multiple `vaddr`s
    /// mapped to that `paddr`.
    fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
        // FixMe: Use macro to implement it. Ref: __va in [asm/page.h].
        unsafe {
            va!(linux_phys_to_virt(paddr.as_usize()))
        }
    }

    /// Translates a virtual address to a physical address.
    ///
    /// It is a reverse operation of [`phys_to_virt`]. It requires that the
    /// `vaddr` must be available through the [`phys_to_virt`] translation.
    /// It **cannot** be used to translate arbitrary virtual addresses.
    fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
        // FixMe: Use macro to implement it. Ref: __pa in [asm/page.h].
        unsafe {
            pa!(linux_virt_to_phys(vaddr.as_usize()))
        }
    }
}

unsafe extern "C" {
    fn linux_virt_to_phys(va: usize) -> usize;
    fn linux_phys_to_virt(pa: usize) -> usize;
}
