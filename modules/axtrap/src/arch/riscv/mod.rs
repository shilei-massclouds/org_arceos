use riscv::register::stvec;
use riscv::register::scause::{self, Exception as E, Trap};
use axhal::arch::TrapFrame;
use riscv::register::stval;
use axhal::trap::TRAPFRAME_SIZE;
use axsyscall::SyscallArgs;

axhal::include_asm_marcos!();

core::arch::global_asm!(
    include_str!("trap.S"),
    trapframe_size = const TRAPFRAME_SIZE,
);

/// Writes Supervisor Trap Vector Base Address Register (`stvec`).
#[inline]
pub fn set_trap_vector_base(stvec: usize) {
    unsafe { stvec::write(stvec, stvec::TrapMode::Direct) }
}

#[no_mangle]
pub fn riscv_trap_handler(tf: &mut TrapFrame, _from_user: bool) {
    let scause = scause::read();
    match scause.cause() {
        Trap::Exception(E::Breakpoint) => handle_breakpoint(&mut tf.sepc),
        Trap::Exception(E::UserEnvCall) => handle_linux_syscall(tf),
        Trap::Exception(E::InstructionPageFault) => {
            handle_page_fault(stval::read(), 0);
        },
        Trap::Exception(E::LoadPageFault) => {
            handle_page_fault(stval::read(), 1);
        },
        Trap::Exception(E::StorePageFault) => {
            handle_page_fault(stval::read(), 2);
        },
        Trap::Interrupt(_) => handle_irq_extern(scause.bits()),
        _ => {
            panic!(
                "Unhandled trap {:?} @ {:#x}:\n{:#x?}",
                scause.cause(),
                tf.sepc,
                tf
            );
        }
    }
}

/// Call page fault handler.
fn handle_page_fault(badaddr: usize, _cause: usize) {
    error!("handle_page_fault...");
    mmap::faultin_page(badaddr);
}

/// Call the external IRQ handler.
fn handle_irq_extern(irq_num: usize) {
    error!("handle_irq_extern irq: {:#X} ...", irq_num);
    let guard = kernel_guard::NoPreempt::new();
    axirq::dispatch_irq(irq_num);
    drop(guard); // rescheduling may occur when preemption is re-enabled.
}

fn handle_breakpoint(sepc: &mut usize) {
    debug!("Exception(Breakpoint) @ {:#x} ", sepc);
    *sepc += 2
}

fn handle_linux_syscall(tf: &mut TrapFrame) {
    error!("handle_linux_syscall");
    syscall(tf, axsyscall::do_syscall);
}

fn syscall_args(tf: &TrapFrame) -> SyscallArgs {
    [
        tf.regs.a0, tf.regs.a1, tf.regs.a2,
        tf.regs.a3, tf.regs.a4, tf.regs.a5,
    ]
}

fn syscall<F>(tf: &mut TrapFrame, do_syscall: F)
where
    F: FnOnce(SyscallArgs, usize) -> usize
{
    error!("Syscall: {:#x}", tf.regs.a7);
    let args = syscall_args(tf);
    tf.regs.a0 = do_syscall(args, tf.regs.a7);
    tf.sepc += 4;
}
