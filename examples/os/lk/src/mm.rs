//! Handle #PF

use axhal::trap::{PAGE_FAULT, register_trap_handler};
use axhal::mem::VirtAddr;
use axhal::paging::MappingFlags;

#[register_trap_handler(PAGE_FAULT)]
fn page_fault_handler(vaddr: VirtAddr, access_flags: MappingFlags, is_user: bool, regs_ptr: usize) -> bool {
    log::trace!(
        "Page fault @ {:#x}, access_flags: {:?}, is_user: {}",
        vaddr, access_flags, is_user
    );
    unsafe {
        handle_page_fault(regs_ptr);
    }
    true
}

unsafe extern "C" {
    fn handle_page_fault(regs: usize);
}
