use page_table_entry::MappingFlags;
use riscv::interrupt::Trap;
use riscv::interrupt::supervisor::{Exception as E, Interrupt as I};
use riscv::register::{scause, stval};

use super::TrapFrame;

core::arch::global_asm!(
    include_asm_macros!(),
    include_str!("trap.S"),
    trapframe_size = const core::mem::size_of::<TrapFrame>(),
);

#[cfg(linux_adaptor)]
fn handle_breakpoint(sepc: &mut usize) {
    report_bug(*sepc);
    *sepc += 2
}

// For linux bug.
#[repr(C)]
#[derive(Debug)]
struct BugEntry {
    bug_addr_disp:  i32,
    file_disp:      i32,
    line:   u16,
    flags:  u16,
}

#[cfg(linux_adaptor)]
fn bug_relative_offset(ptr_offset: *const i32) -> usize {
    (ptr_offset as isize + unsafe { *ptr_offset } as isize) as usize
}

#[cfg(linux_adaptor)]
fn report_bug(addr: usize) {
    unsafe extern "C" {
        fn __start___bug_table();
        fn __stop___bug_table();
    }
    error!("bug_table ({:#x}, {:#x}) entry({})",
           __start___bug_table as usize, __stop___bug_table as usize,
           core::mem::size_of::<BugEntry>());

    let bug_table_ptr = __start___bug_table as *const BugEntry;
    let bug_table_len = __stop___bug_table as usize - __start___bug_table as usize;

    let bugs = unsafe {
        core::slice::from_raw_parts(bug_table_ptr, bug_table_len)
    };

    for bug in bugs {
        if bug_relative_offset(&bug.bug_addr_disp) == addr {
            let fname_ptr = bug_relative_offset(&bug.file_disp) as *const u8;
            let fname = unsafe {
                core::ffi::CStr::from_ptr(fname_ptr)
            };
            panic!("BUG: line {} in {:?}", bug.line, fname);
        }
    }

    panic!("For linux_adaptor: let ebreak @ {:#x} cause PANIC!", addr);
}

#[cfg(not(linux_adaptor))]
fn handle_breakpoint(sepc: &mut usize) {
    debug!("Exception(Breakpoint) @ {:#x} ", sepc);
    *sepc += 2
}

fn handle_page_fault(tf: &TrapFrame, mut access_flags: MappingFlags, is_user: bool) {
    if is_user {
        access_flags |= MappingFlags::USER;
    }
    let vaddr = va!(stval::read());
    if !handle_trap!(PAGE_FAULT, vaddr, access_flags, is_user) {
        panic!(
            "Unhandled {} Page Fault @ {:#x}, fault_vaddr={:#x} ({:?}):\n{:#x?}",
            if is_user { "User" } else { "Supervisor" },
            tf.sepc,
            vaddr,
            access_flags,
            tf,
        );
    }
}

#[unsafe(no_mangle)]
fn riscv_trap_handler(tf: &mut TrapFrame, from_user: bool) {
    let scause = scause::read();
    if let Ok(cause) = scause.cause().try_into::<I, E>() {
        match cause {
            #[cfg(feature = "uspace")]
            Trap::Exception(E::UserEnvCall) => {
                tf.regs.a0 = crate::trap::handle_syscall(tf, tf.regs.a7) as usize;
                tf.sepc += 4;
            }
            Trap::Exception(E::LoadPageFault) => {
                handle_page_fault(tf, MappingFlags::READ, from_user)
            }
            Trap::Exception(E::StorePageFault) => {
                handle_page_fault(tf, MappingFlags::WRITE, from_user)
            }
            Trap::Exception(E::InstructionPageFault) => {
                handle_page_fault(tf, MappingFlags::EXECUTE, from_user)
            }
            Trap::Exception(E::Breakpoint) => handle_breakpoint(&mut tf.sepc),
            Trap::Interrupt(_) => {
                handle_trap!(IRQ, scause.bits());
            }
            _ => {
                panic!("Unhandled trap {:?} @ {:#x}:\n{:#x?}", cause, tf.sepc, tf);
            }
        }
    } else {
        panic!(
            "Unknown trap {:?} @ {:#x}:\n{:#x?}",
            scause.cause(),
            tf.sepc,
            tf
        );
    }
}
