include_asm_marcos!();
use crate::trap::TRAPFRAME_SIZE;
pub fn ret_from_fork(kstack_sp: usize) {
    unsafe {
        core::arch::asm!(
            r"
            mv  sp, {kstack_sp}
            addi t0, sp, {tramframe_size}
            csrw sscratch, t0
            RESTORE_REGS 1
            sret
            ",
            kstack_sp = in(reg) kstack_sp,
            tramframe_size = const TRAPFRAME_SIZE,
        );
    };
}

core::arch::global_asm!(
    r"
    .section .text
    .balign 4
    .global __user_rt_sigreturn
    __user_rt_sigreturn:
    li a7, 139 // __NR_rt_sigreturn
    scall
    "
);
