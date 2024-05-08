use axhal::arch::{TrapFrame, local_flush_icache_all};
use axtype::align_down;
use crate::{RTSigFrame, KSignal, SIGFRAME_SIZE};
use crate::{setup_sigcontext, restore_sigcontext};

pub fn rt_sigreturn() -> usize {
    info!("sigreturn ...");

    let ctx = taskctx::current_ctx();
    let tf = ctx.pt_regs();

    let frame_addr = tf.regs.sp;
    let frame = unsafe { &mut(*(frame_addr as *mut RTSigFrame)) };

    // Validation: sigreturn_code must be 'li a7, 139; scall'.
    // For riscv64, NR_sigreturn == 139.
    assert_eq!(frame.sigreturn_code, 0x7308B00893);

    //__copy_from_user(&set, &frame->uc.uc_sigmask, sizeof(set))
    //set_current_blocked(&set);

    restore_sigcontext(tf, frame);

    // Todo: restore_altstack
    return tf.regs.a0;
}

fn get_sigframe(tf: &TrapFrame) -> usize {
    let sp = tf.regs.sp - SIGFRAME_SIZE;
    /* Align the stack frame. */
    align_down(sp, 16)
}

pub fn handle_signal(ksig: &KSignal, tf: &mut TrapFrame) {
    extern "C" {
        fn __user_rt_sigreturn();
    }

    let frame_addr = get_sigframe(tf);
    let frame = unsafe { &mut(*(frame_addr as *mut RTSigFrame)) };
    setup_sigcontext(frame, tf);

    // Note: Now we store user_rt_sigreturn code into user stack,
    // but it's unsafe to execute code on stack.
    // Consider to implement vdso and put that code in vdso page.
    let user_rt_sigreturn = __user_rt_sigreturn as usize as *const usize;
    frame.sigreturn_code = unsafe { *user_rt_sigreturn };

    let ra = &(frame.sigreturn_code) as *const usize;
    /* Make sure the two instructions are pushed to icache. */
    local_flush_icache_all();
    tf.regs.ra = ra as usize;

    assert!(ksig.action.handler != 0);
    tf.sepc = ksig.action.handler;
    tf.regs.sp = frame_addr;
    tf.regs.a0 = ksig.signo;    // a0: signal number
    /*
    tf.regs.a1 = &frame.info;   // a1: siginfo pointer
    tf.regs.a2 = &frame.uc;     // a2: ucontext pointer
    */

    info!("handle_signal signo {} frame {:#X} tf.epc {:#x}",
          ksig.signo, frame.sigreturn_code, tf.sepc);
}
