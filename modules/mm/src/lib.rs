#![no_std]
#![feature(btree_cursors)]

extern crate log;
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::cell::OnceCell;
use axfile::fops::File;
use axhal::paging::pgd_alloc;
use axhal::paging::MappingFlags;
use axhal::paging::PageTable;
use axhal::paging::PagingResult;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use spinbase::SpinNoIrq;
use mutex::Mutex;

pub type FileRef = Arc<Mutex<File>>;

static MM_UNIQUE_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Clone)]
pub struct VmAreaStruct {
    pub vm_start: usize,
    pub vm_end: usize,
    pub vm_pgoff: usize,
    pub vm_file: OnceCell<FileRef>,
    pub vm_flags: usize,
}

impl VmAreaStruct {
    pub fn new(
        vm_start: usize,
        vm_end: usize,
        vm_pgoff: usize,
        vm_file: Option<FileRef>,
        vm_flags: usize,
    ) -> Self {
        let vma = Self {
            vm_start,
            vm_end,
            vm_pgoff,
            vm_file: OnceCell::new(),
            vm_flags,
        };
        if let Some(f) = vm_file {
            let _ = vma.vm_file.set(f);
        }
        vma
    }
}

pub struct MmStruct {
    id: usize,
    pub vmas: BTreeMap<usize, VmAreaStruct>,
    pgd: Arc<SpinNoIrq<PageTable>>,
    brk: usize,
}

impl MmStruct {
    pub fn new() -> Self {
        Self {
            id: MM_UNIQUE_ID.fetch_add(1, Ordering::SeqCst),
            vmas: BTreeMap::new(),
            pgd: Arc::new(SpinNoIrq::new(pgd_alloc())),
            brk: 0,
        }
    }

    pub fn dup(&self) -> Self {
        Self {
            id: MM_UNIQUE_ID.fetch_add(1, Ordering::SeqCst),
            vmas: self.vmas.clone(),
            pgd: self.pgd.clone(),
            brk: self.brk,
        }
    }

    pub fn pgd(&self) -> Arc<SpinNoIrq<PageTable>> {
        self.pgd.clone()
    }

    pub fn root_paddr(&self) -> usize {
        self.pgd.lock().root_paddr().into()
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn brk(&self) -> usize {
        self.brk
    }

    pub fn set_brk(&mut self, brk: usize) {
        self.brk = brk;
    }

    pub fn map_region(&self, va: usize, pa: usize, len: usize, _uflags: usize) -> PagingResult {
        let flags =
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE | MappingFlags::USER;
        self.pgd
            .lock()
            .map_region(va.into(), pa.into(), len, flags, true)
    }

    pub fn unmap_region(&self, va: usize, len: usize) -> PagingResult {
        self.pgd.lock().unmap_region(va.into(), len)
    }
}
