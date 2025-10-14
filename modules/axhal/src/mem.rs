//! Physical memory management.

use core::fmt;

use axconfig::plat::{PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE, PHYS_VIRT_OFFSET};

#[doc(no_inline)]
pub use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PhysAddr, VirtAddr};

bitflags::bitflags! {
    /// The flags of a physical memory region.
    pub struct MemRegionFlags: usize {
        /// Readable.
        const READ          = 1 << 0;
        /// Writable.
        const WRITE         = 1 << 1;
        /// Executable.
        const EXECUTE       = 1 << 2;
        /// Device memory. (e.g., MMIO regions)
        const DEVICE        = 1 << 4;
        /// Uncachable memory. (e.g., framebuffer)
        const UNCACHED      = 1 << 5;
        /// Reserved memory, do not use for allocation.
        const RESERVED      = 1 << 6;
        /// Free memory for allocation.
        const FREE          = 1 << 7;
    }
}

impl fmt::Debug for MemRegionFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/// A physical memory region.
#[derive(Debug)]
pub struct MemRegion {
    /// The start physical address of the region.
    pub paddr: PhysAddr,
    /// The size in bytes of the region.
    pub size: usize,
    /// The region flags, see [`MemRegionFlags`].
    pub flags: MemRegionFlags,
    /// The region name, used for identification.
    pub name: &'static str,
}

/// Converts a virtual address to a physical address.
///
/// It assumes that there is a linear mapping with the offset
/// [`PHYS_VIRT_OFFSET`], that maps all the physical memory to the virtual
/// space at the address plus the offset. So we have
/// `paddr = vaddr - PHYS_VIRT_OFFSET`.
#[inline]
pub const fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    pa!(vaddr.as_usize() - PHYS_VIRT_OFFSET)
}

/// Converts a physical address to a virtual address.
///
/// It assumes that there is a linear mapping with the offset
/// [`PHYS_VIRT_OFFSET`], that maps all the physical memory to the virtual
/// space at the address plus the offset. So we have
/// `vaddr = paddr + PHYS_VIRT_OFFSET`.
#[inline]
pub const fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    va!(paddr.as_usize() + PHYS_VIRT_OFFSET)
}

/// Returns an iterator over all physical memory regions.
pub fn memory_regions() -> impl Iterator<Item = MemRegion> {
    kernel_image_regions()
        .chain(kallsyms_region())
        .chain(crate::platform::mem::platform_regions())
}

/// Returns the memory regions of the kernel image (code and data sections).
fn kernel_image_regions() -> impl Iterator<Item = MemRegion> {
    [
        MemRegion {
            paddr: virt_to_phys((_stext as usize).into()),
            size: _etext as usize - _stext as usize,
            flags: MemRegionFlags::RESERVED | MemRegionFlags::READ | MemRegionFlags::EXECUTE,
            name: ".text",
        },
        MemRegion {
            paddr: virt_to_phys((_srodata as usize).into()),
            size: _erodata as usize - _srodata as usize,
            flags: MemRegionFlags::RESERVED | MemRegionFlags::READ,
            name: ".rodata",
        },
        MemRegion {
            paddr: virt_to_phys((_sdata as usize).into()),
            size: _edata as usize - _sdata as usize,
            flags: MemRegionFlags::RESERVED | MemRegionFlags::READ | MemRegionFlags::WRITE,
            name: ".data .tdata .tbss .percpu",
        },
        MemRegion {
            paddr: virt_to_phys((boot_stack as usize).into()),
            size: boot_stack_top as usize - boot_stack as usize,
            flags: MemRegionFlags::RESERVED | MemRegionFlags::READ | MemRegionFlags::WRITE,
            name: "boot stack",
        },
        MemRegion {
            paddr: virt_to_phys((_sbss as usize).into()),
            size: _ebss as usize - _sbss as usize,
            flags: MemRegionFlags::RESERVED | MemRegionFlags::READ | MemRegionFlags::WRITE,
            name: ".bss",
        },
    ]
    .into_iter()
}

/// Returns the default MMIO memory regions (from [`axconfig::MMIO_REGIONS`]).
#[allow(dead_code)]
pub(crate) fn default_mmio_regions() -> impl Iterator<Item = MemRegion> {
    axconfig::devices::MMIO_REGIONS.iter().map(|reg| MemRegion {
        paddr: reg.0.into(),
        size: reg.1,
        flags: MemRegionFlags::RESERVED
            | MemRegionFlags::DEVICE
            | MemRegionFlags::READ
            | MemRegionFlags::WRITE,
        name: "mmio",
    })
}

/// Kallsyms area head which follows '_ekernel'.
struct KallsymsHead {
    magic: [u8; 4],
    size: u32,
}

pub const HEAD_MAGIC: [u8; 4] = [b'k', b'a', b'l', b'l'];
pub const TAIL_MAGIC: [u8; 4] = [b's', b'y', b'm', b's'];

#[used]
#[unsafe(link_section = ".kallsyms")]
static _KALLSYMS_DUMMY: [u8; 16] = [0; 16];

pub fn kallsyms_size() -> usize {
    static mut SIZE: usize = 0;
    static mut _INITED: bool = false;

    unsafe {
        if !_INITED {
            let ptr = _kallsyms as usize as *const u8;

            let head_ptr = ptr as *const u64;
            let head = core::mem::transmute::<u64, KallsymsHead>(*head_ptr);
            if head.magic == HEAD_MAGIC {
                let size = u32::from_be(head.size) as usize;
                let tail_ptr = ptr.add(4 + 4 + size);
                if core::slice::from_raw_parts(tail_ptr, 4) == TAIL_MAGIC {
                    SIZE = size;
                }
            }
            _INITED = true;
        }
        SIZE
    }
}

/// Returns kallsyms region.
#[allow(dead_code)]
pub(crate) fn kallsyms_region() -> impl Iterator<Item = MemRegion> {
    let mut size = kallsyms_size();
    if size == 0 {
        panic!("No kallsyms segment.");
    }

    // Add size of fields [head|size|tail] (4bytes + 4bytes + 4bytes)
    size += 12;

    let base = _kallsyms as usize;
    let start = virt_to_phys(base.into());
    assert!(start.is_aligned_4k());
    let end = virt_to_phys((base + size).into()).align_up_4k();
    core::iter::once(MemRegion {
        paddr: start,
        size: end.as_usize() - start.as_usize(),
        flags: MemRegionFlags::READ,
        name: "kallsyms",
    })
}

/// Returns the default free memory regions (kernel image end to physical memory end).
#[allow(dead_code)]
pub(crate) fn default_free_regions() -> impl Iterator<Item = MemRegion> {
    let mut kallsyms_size = kallsyms_size();
    if kallsyms_size > 0 {
        // Add size of fields [head|size|tail] (4bytes + 4bytes + 4bytes)
        kallsyms_size += 12;
    }
    let start = _ekernel as usize + kallsyms_size;
    error!("start: {:#X} {:#X}", start, _ekernel as usize);

    let start = virt_to_phys(start.into()).align_up_4k();
    let end = pa!(PHYS_MEMORY_BASE + PHYS_MEMORY_SIZE).align_down_4k();
    core::iter::once(MemRegion {
        paddr: start,
        size: end.as_usize() - start.as_usize(),
        flags: MemRegionFlags::FREE | MemRegionFlags::READ | MemRegionFlags::WRITE,
        name: "free memory",
    })
}

/// Fills the `.bss` section with zeros.
#[allow(dead_code)]
pub(crate) fn clear_bss() {
    unsafe {
        core::slice::from_raw_parts_mut(_sbss as usize as *mut u8, _ebss as usize - _sbss as usize)
            .fill(0);
    }
}

unsafe extern "C" {
    fn _stext();
    fn _etext();
    fn _srodata();
    fn _erodata();
    fn _sdata();
    fn _edata();
    fn _sbss();
    fn _ebss();
    fn _ekernel();
    fn boot_stack();
    fn boot_stack_top();
    fn _kallsyms();
}
