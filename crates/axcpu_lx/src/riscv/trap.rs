use riscv::interrupt::supervisor::{Exception as E, Interrupt as I};
use riscv::interrupt::Trap;
#[cfg(feature = "fp-simd")]
use riscv::register::sstatus;
use riscv::register::{scause, stval};
use page_table_entry::MappingFlags;

use super::TrapFrame;
use crate::trap::PageFaultFlags;

use linux_config::*;

/*
 *  All offsets prefixed by 'TASK_TI_' according to
 *  struct thread_info in linux kernel.
 *
 *  struct thread_info {
 *      unsigned long   flags;
 *      int             preempt_count;
 *      long            kernel_sp;
 *      long            user_sp;
 *      int             cpu;
 *      unsigned long   syscall_work;
 *      unsigned long   a0, a1, a2;
 *  };
 */

const TASK_TI_FLAGS         : usize = 0;
const TASK_TI_PREEMPT_COUNT : usize = 8;
const TASK_TI_KERNEL_SP     : usize = 16;
const TASK_TI_USER_SP       : usize = 24;
const TASK_TI_CPU           : usize = 32;

const TASK_TI_A0 : usize = 48;
const TASK_TI_A1 : usize = 56;
const TASK_TI_A2 : usize = 64;

const PT_EPC: usize = 0;
const PT_RA: usize = 8;
const PT_SP: usize = 16;
const PT_GP: usize = 24;
const PT_TP: usize = 32;
const PT_T0: usize = 40;
const PT_T1: usize = 48;
const PT_T2: usize = 56;
const PT_S0: usize = 64;
const PT_S1: usize = 72;
const PT_A0: usize = 80;
const PT_A1: usize = 88;
const PT_A2: usize = 96;
const PT_A3: usize = 104;
const PT_A4: usize = 112;
const PT_A5: usize = 120;
const PT_A6: usize = 128;
const PT_A7: usize = 136;
const PT_S2: usize = 144;
const PT_S3: usize = 152;
const PT_S4: usize = 160;
const PT_S5: usize = 168;
const PT_S6: usize = 176;
const PT_S7: usize = 184;
const PT_S8: usize = 192;
const PT_S9: usize = 200;
const PT_S10: usize = 208;
const PT_S11: usize = 216;
const PT_T3: usize = 224;
const PT_T4: usize = 232;
const PT_T5: usize = 240;
const PT_T6: usize = 248;

const PT_STATUS : usize = 256;
const PT_BADADDR: usize = 264;
const PT_CAUSE  : usize = 272;
const PT_ORIG_A0: usize = 280;

// Defined by Risc-V ISA.
const EXC_INST_PAGE_FAULT   : usize = 12;
const EXC_LOAD_PAGE_FAULT   : usize = 13;
const EXC_STORE_PAGE_FAULT  : usize = 15;

core::arch::global_asm!(
    include_asm_macros!(),
    include_str!("trap.S"),
    PT_SIZE_ON_STACK = const PT_SIZE_ON_STACK,
    PT_EPC = const PT_EPC,
    PT_RA = const PT_RA,
    PT_SP = const PT_SP,
    PT_GP = const PT_GP,
    PT_TP = const PT_TP,
    PT_T0 = const PT_T0,
    PT_T1 = const PT_T1,
    PT_T2 = const PT_T2,
    PT_T3 = const PT_T3,
    PT_T4 = const PT_T4,
    PT_T5 = const PT_T5,
    PT_T6 = const PT_T6,
    PT_A0 = const PT_A0,
    PT_A1 = const PT_A1,
    PT_A2 = const PT_A2,
    PT_A3 = const PT_A3,
    PT_A4 = const PT_A4,
    PT_A5 = const PT_A5,
    PT_A6 = const PT_A6,
    PT_A7 = const PT_A7,
    PT_S0 = const PT_S0,
    PT_S1 = const PT_S1,
    PT_S2 = const PT_S2,
    PT_S3 = const PT_S3,
    PT_S4 = const PT_S4,
    PT_S5 = const PT_S5,
    PT_S6 = const PT_S6,
    PT_S7 = const PT_S7,
    PT_S8 = const PT_S8,
    PT_S9 = const PT_S9,
    PT_S10 = const PT_S10,
    PT_S11 = const PT_S11,
    PT_STATUS = const PT_STATUS,
    PT_BADADDR = const PT_BADADDR,
    PT_CAUSE = const PT_CAUSE,
    //PT_ORIG_A0 = const PT_ORIG_A0,
    TASK_TI_KERNEL_SP = const TASK_TI_KERNEL_SP,
    TASK_TI_USER_SP = const TASK_TI_USER_SP,
    TASK_TI_CPU = const TASK_TI_CPU,
    TASK_TI_A0 = const TASK_TI_A0,
    TASK_TI_A1 = const TASK_TI_A1,
    TASK_TI_A2 = const TASK_TI_A2,
    EXC_INST_PAGE_FAULT = const EXC_INST_PAGE_FAULT,
    EXC_LOAD_PAGE_FAULT = const EXC_LOAD_PAGE_FAULT,
    EXC_STORE_PAGE_FAULT = const EXC_STORE_PAGE_FAULT,
    SR_SUM = const SR_SUM,
    SR_FS_VS = const SR_FS_VS,
    SR_SPP = const SR_SPP,
    RISCV_LGPTR = const RISCV_LGPTR,
);

#[unsafe(no_mangle)]
fn ax_handle_ebreak(ptr_regs: usize)
{
    let ptr_regs = ptr_regs as *mut PtRegs;
    unsafe {
        handle_breakpoint(&mut ((*ptr_regs).epc))
    }
}

fn handle_breakpoint(sepc: &mut usize) {
    debug!("Exception(Breakpoint) @ {sepc:#x} ");
    *sepc += 2
}

#[unsafe(no_mangle)]
fn ax_handle_page_fault(ptr_regs: usize)
{
    let ptr_regs = ptr_regs as *const PtRegs;
    let regs = unsafe { &(*ptr_regs) };
    let is_user = (regs.status & SR_SPP) == 0;
    let flags = match regs.cause {
        EXC_INST_PAGE_FAULT => PageFaultFlags::EXECUTE,
        EXC_LOAD_PAGE_FAULT => PageFaultFlags::READ,
        EXC_STORE_PAGE_FAULT => PageFaultFlags::WRITE,
        _ => panic!("bad exception type {}", regs.cause),
    };
    handle_page_fault(regs, flags, is_user);
}

fn handle_page_fault(tf: &PtRegs, mut access_flags: PageFaultFlags, is_user: bool) {
    if is_user {
        access_flags |= PageFaultFlags::USER;
    }
    let vaddr = va!(stval::read());
    if !handle_trap!(PAGE_FAULT, vaddr, access_flags, is_user) {
        panic!(
            "Unhandled {} Page Fault @ {:#x}, fault_vaddr={:#x} ({:?}):\n{:#x?}",
            if is_user { "User" } else { "Supervisor" },
            tf.epc,
            vaddr,
            access_flags,
            tf
        );
    }
}

/*
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
                handle_page_fault(tf, PageFaultFlags::READ, from_user)
            }
            Trap::Exception(E::StorePageFault) => {
                handle_page_fault(tf, PageFaultFlags::WRITE, from_user)
            }
            Trap::Exception(E::InstructionPageFault) => {
                handle_page_fault(tf, PageFaultFlags::EXECUTE, from_user)
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
            "Unknown trap {:#x?} @ {:#x}:\n{:#x?}",
            scause.cause(),
            tf.sepc,
            tf
        );
    }

    // Update tf.sstatus to preserve current hardware FS state
    // This replaces the assembly-level FS handling workaround
    #[cfg(feature = "fp-simd")]
    tf.sstatus.set_fs(sstatus::read().fs());
}
*/
