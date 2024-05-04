#![no_std]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
extern crate alloc;
use axerrno::LinuxResult;
use axfile::fops::File;
use axhal::arch::TASK_UNMAPPED_BASE;
use axhal::mem::{phys_to_virt, virt_to_phys};
use axio::SeekFrom;
use core::ops::Bound;
use memory_addr::{align_up_4k, align_down_4k, is_aligned_4k, PAGE_SHIFT, PAGE_SIZE_4K};
pub use mm::FileRef;
use mm::VmAreaStruct;
use axerrno::LinuxError;
use axhal::arch::TASK_SIZE;

/// Share changes
const MAP_SHARED: usize = 0x01;
/// Changes are private
const MAP_PRIVATE: usize = 0x02;
/// share + validate extension flags
const MAP_SHARED_VALIDATE: usize = 0x03;

/// Interpret addr exactly.
pub const MAP_FIXED: usize = 0x10;
/// Don't use a file.
pub const MAP_ANONYMOUS: usize = 0x20;

/// stack-like segment
const MAP_GROWSDOWN: usize = 0x0100;
/// ETXTBSY
const MAP_DENYWRITE: usize = 0x0800;
/// mark it as an executable */
const MAP_EXECUTABLE: usize= 0x1000;
/// pages are locked */
const MAP_LOCKED: usize    = 0x2000;
/// don't check for reservations */
const MAP_NORESERVE: usize = 0x4000;

const MAP_32BIT: usize = 0;
const MAP_HUGE_2MB: usize = 0;
const MAP_HUGE_1GB: usize = 0;

/* 0x0100 - 0x4000 flags are defined in asm-generic/mman.h */
/// populate (prefault) pagetables
const MAP_POPULATE: usize = 0x008000;
/// do not block on IO
const MAP_NONBLOCK: usize = 0x010000;
/// give out an address that is best suited for process/thread stacks
const MAP_STACK: usize =    0x020000;
/// create a huge page mapping
const MAP_HUGETLB: usize =  0x040000;
/// perform synchronous page faults for the mapping
//const MAP_SYNC: usize =     0x080000;

/// MAP_FIXED which doesn't unmap underlying mapping
pub const MAP_FIXED_NOREPLACE: usize = 0x100000;

/// For anonymous mmap, memory could be uninitialized
const MAP_UNINITIALIZED: usize = 0x4000000;

const LEGACY_MAP_MASK: usize =
    MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_DENYWRITE |
    MAP_EXECUTABLE | MAP_UNINITIALIZED | MAP_GROWSDOWN | MAP_LOCKED | MAP_NORESERVE |
    MAP_POPULATE | MAP_NONBLOCK | MAP_STACK | MAP_HUGETLB | MAP_32BIT |
    MAP_HUGE_2MB | MAP_HUGE_1GB;

pub fn mmap(
    va: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: usize,
    offset: usize,
) -> LinuxResult<usize> {
    let current = task::current();
    let filetable = current.filetable.lock();
    let file = if (flags & MAP_ANONYMOUS) != 0 {
        None
    } else {
        if fd == usize::MAX {
            return Err(LinuxError::EBADF);
        }
        if (flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE {
            // Todo: flags_mask also includes file->f_op->mmap_supported_flags
            let flags_mask = LEGACY_MAP_MASK;
            if (flags & !flags_mask) != 0 {
                return Err(LinuxError::EOPNOTSUPP);
            }
        }
        filetable.get_file(fd)
    };
    if len == 0 {
        return Err(LinuxError::EINVAL);
    }
    _mmap(va, len, prot, flags, file, offset)
}

pub fn _mmap(
    mut va: usize,
    mut len: usize,
    _prot: usize,
    mut flags: usize,
    file: Option<FileRef>,
    offset: usize,
) -> LinuxResult<usize> {
    assert!(is_aligned_4k(va));
    len = align_up_4k(len);
    info!("mmap va {:#X} offset {:#X}", va, offset);

    /* force arch specific MAP_FIXED handling in get_unmapped_area */
    if (flags & MAP_FIXED_NOREPLACE) != 0 {
        flags |= MAP_FIXED;
    }

    if (flags & MAP_FIXED) == 0 {
        va = get_unmapped_vma(va, len);
        info!("Get unmapped vma {:#X}", va);
    }

    if va > TASK_SIZE - len {
        return Err(LinuxError::ENOMEM);
    }

    let mm = task::current().mm();
    if let Some(mut overlap) = find_overlap(va, len) {
        info!("find overlap {:#X}-{:#X}", overlap.vm_start, overlap.vm_end);
        assert!(
            overlap.vm_start <= va && va + len <= overlap.vm_end,
            "{:#X}-{:#X}; overlap {:#X}-{:#X}",
            va,
            va + len,
            overlap.vm_start,
            overlap.vm_end
        );

        if (flags & MAP_FIXED_NOREPLACE) != 0 {
            return Err(LinuxError::EEXIST);
        }

        if va + len < overlap.vm_end {
            let bias = (va + len - overlap.vm_start) >> PAGE_SHIFT;
            let mut new = overlap.clone();
            new.vm_start = va + len;
            new.vm_pgoff += bias;
            mm.lock().vmas.insert(va + len, new);
        }
        if va > overlap.vm_start {
            overlap.vm_end = va;
            mm.lock().vmas.insert(overlap.vm_start, overlap);
        }
    }

    info!(
        "mmap region: {:#X} - {:#X}, flags: {:#X}",
        va,
        va + len,
        flags
    );
    let vma = VmAreaStruct::new(va, va + len, offset >> PAGE_SHIFT, file, flags);
    mm.lock().vmas.insert(va, vma);

    Ok(va)
}

fn find_overlap(va: usize, len: usize) -> Option<VmAreaStruct> {
    debug!("find_overlap: va {:#X} len {:#X}", va, len);

    let mm = task::current().mm();
    let locked_mm = mm.lock();
    let ret = locked_mm.vmas.iter().find(|(_, vma)| {
        in_vma(va, va + len, vma) || in_range(vma.vm_start, vma.vm_end, va, va + len)
    });

    if let Some((key, _)) = ret {
        warn!("### Removed!!!");
        mm.lock().vmas.remove(&key)
    } else {
        None
    }
}

#[inline]
const fn in_range(start: usize, end: usize, r_start: usize, r_end: usize) -> bool {
    (start >= r_start && start < r_end) || (end > r_start && end <= r_end)
}

#[inline]
const fn in_vma(start: usize, end: usize, vma: &VmAreaStruct) -> bool {
    in_range(start, end, vma.vm_start, vma.vm_end)
}

pub fn get_unmapped_vma(_va: usize, len: usize) -> usize {
    let mm = task::current().mm();
    let locked_mm = mm.lock();
    let mut gap_end = TASK_UNMAPPED_BASE;
    for (_, vma) in locked_mm.vmas.iter().rev() {
        debug!(
            "get_unmapped_vma iterator: {:#X} {:#X} {:#X}",
            vma.vm_start, vma.vm_end, gap_end
        );
        if vma.vm_end > gap_end {
            continue;
        }
        if gap_end - vma.vm_end >= len {
            info!(
                "get_unmapped_vma: {:#X} {:#X} {:#X}",
                vma.vm_start, vma.vm_end, gap_end
            );
            return gap_end - len;
        }
        gap_end = vma.vm_start;
    }
    unimplemented!("NO available unmapped vma!");
}

pub fn faultin_page(va: usize) -> usize {
    info!("faultin_page... va {:#X}", va);
    let mm = task::current().mm();
    let mut locked_mm = mm.lock();

    let vma = locked_mm
        .vmas
        .upper_bound(Bound::Included(&va))
        .value()
        .unwrap();
    assert!(
        va >= vma.vm_start && va < vma.vm_end,
        "va {:#X} in {:#X} - {:#X}",
        va,
        vma.vm_start,
        vma.vm_end
    );
    let va = align_down_4k(va);
    let delta = va - vma.vm_start;
    //let flags = vma.vm_flags;
    let offset = (vma.vm_pgoff << PAGE_SHIFT) + delta;

    let direct_va: usize = axalloc::global_allocator()
        .alloc_pages(1, PAGE_SIZE_4K)
        .unwrap();

    // Todo: check whether we need to zero it.
    let buf = unsafe { core::slice::from_raw_parts_mut(direct_va as *mut u8, PAGE_SIZE_4K) };
    buf.fill(0);

    let pa = virt_to_phys(direct_va.into()).into();

    if vma.vm_file.get().is_some() {
        let f = vma.vm_file.get().unwrap().clone();
        fill_cache(pa, PAGE_SIZE_4K, &mut f.lock(), offset);
    }
    locked_mm.map_region(va, pa, PAGE_SIZE_4K, 1)
        .unwrap_or_else(|e| { panic!("{:?}", e) });

    // Todo: temporarily record mapped va->pa(direct_va)
    locked_mm.mapped.push((va, direct_va));

    phys_to_virt(pa.into()).into()
}

fn fill_cache(pa: usize, len: usize, file: &mut File, offset: usize) {
    let offset = align_down_4k(offset);
    let va = phys_to_virt(pa.into()).as_usize();

    let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) };

    info!("offset {:#X} len {:#X}", offset, len);
    let _ = file.seek(SeekFrom::Start(offset as u64));

    let mut pos = 0;
    while pos < len {
        let ret = file.read(&mut buf[pos..]).unwrap();
        if ret == 0 {
            break;
        }
        pos += ret;
    }
    buf[pos..].fill(0);
}

pub fn set_brk(va: usize) -> usize {
    // Have a guard for mm to lock this whole function,
    // because mm.brk() and mm.set_brk() should be in a atomic context.
    let mm = task::current().mm();
    let brk = mm.lock().brk();

    assert!(is_aligned_4k(brk));
    debug!("brk!!! {:#x}, {:#x}", va, brk);

    if va == 0 {
        brk
    } else {
        assert!(va > brk);
        let offset = va - brk;
        assert!(is_aligned_4k(offset));
        _mmap(brk, offset, 0, MAP_FIXED | MAP_ANONYMOUS, None, 0).unwrap();
        let _ = faultin_page(brk);
        mm.lock().set_brk(va);
        va
    }
}

pub fn msync(va: usize, len: usize, flags: usize) -> usize {
    info!("msync: va {:#X} len {:#X} flags {:#X}", va, len, flags);

    let mm = task::current().mm();
    let locked_mm = mm.lock();

    let vma = locked_mm
        .vmas
        .upper_bound(Bound::Included(&va))
        .value()
        .unwrap();
    assert!(
        va >= vma.vm_start && va + len <= vma.vm_end,
        "va {:#X} in {:#X} - {:#X}",
        va,
        vma.vm_start,
        vma.vm_end
    );
    info!("msync: {:#X} - {:#X}", va, va + len);

    let delta = va - vma.vm_start;
    let offset = (vma.vm_pgoff << PAGE_SHIFT) + delta;

    if vma.vm_file.get().is_some() {
        let file = vma.vm_file.get().unwrap().clone();
        sync_file(va, len, &mut file.lock(), offset);
    }
    0
}

fn sync_file(va: usize, len: usize, file: &mut File, offset: usize) {
    let buf = unsafe { core::slice::from_raw_parts(va as *const u8, len) };

    let _ = file.seek(SeekFrom::Start(offset as u64));

    let mut pos = 0;
    while pos < len {
        let ret = file.write(&buf[pos..]).unwrap();
        if ret == 0 {
            break;
        }
        pos += ret;
    }
    info!("msync: ok!");
}

pub fn munmap(va: usize, mut len: usize) -> usize {
    assert!(is_aligned_4k(va));
    len = align_up_4k(len);
    info!("munmap {:#X} - {:#X}", va, va + len);

    if let Some(mut overlap) = find_overlap(va, len) {
        info!("find overlap {:#X}-{:#X}", overlap.vm_start, overlap.vm_end);
        assert!(
            overlap.vm_start <= va && va + len <= overlap.vm_end,
            "{:#X}-{:#X}; overlap {:#X}-{:#X}",
            va,
            va + len,
            overlap.vm_start,
            overlap.vm_end
        );

        if va + len < overlap.vm_end {
            let bias = (va + len - overlap.vm_start) >> PAGE_SHIFT;
            let mut new = overlap.clone();
            new.vm_start = va + len;
            new.vm_pgoff += bias;
            let mm = task::current().mm();
            mm.lock().vmas.insert(va + len, new);
        }
        if va > overlap.vm_start {
            overlap.vm_end = va;
            let mm = task::current().mm();
            mm.lock().vmas.insert(overlap.vm_start, overlap);
        }
    }

    let mm = task::current().mm();
    let locked_mm = mm.lock();
    match locked_mm.unmap_region(va, len) {
        Ok(_) => 0,
        Err(e) => {
            warn!("unmap region err: {:#?}", e);
            0
        },
    }
}
