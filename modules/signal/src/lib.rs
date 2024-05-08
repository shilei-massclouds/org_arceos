#![no_std]

#[macro_use]
extern crate log;

use taskctx::Tid;
use task::{SigInfo, SigAction, SA_RESTORER, SA_RESTART};
use axerrno::LinuxResult;
use task::{SIGKILL, SIGSTOP};
use axhal::arch::{TrapFrame, local_flush_icache_all};
use axtype::align_down;

/// si_code values
/// Digital reserves positive values for kernel-generated signals.

// sent by kill, sigsend, raise
const SI_USER: usize = 0;

#[derive(Clone)]
struct UContext {
    _flags: usize,
    _stack: usize,
    _sigmask: usize,
    mcontext: TrapFrame,
}

#[repr(C)]
#[derive(Clone)]
struct RTSigFrame {
    info: SigInfo,
    uc: UContext,
    sigreturn_code: usize,
}

pub const SIGFRAME_SIZE: usize = core::mem::size_of::<RTSigFrame>();

struct KSignal {
    action: SigAction,
    _info: SigInfo,
    signo: usize,
}

//#define SI_KERNEL   0x80        /* sent by the kernel from somewhere */
//#define SI_QUEUE    -1      /* sent by sigqueue */
//#define SI_TIMER    -2      /* sent by timer expiration */
//#define SI_MESGQ    -3      /* sent by real time mesq state change */
//#define SI_ASYNCIO  -4      /* sent by AIO completion */
//#define SI_SIGIO    -5      /* sent by queued SIGIO */
//#define SI_TKILL    -6      /* sent by tkill system call */
//#define SI_DETHREAD -7      /* sent by execve() killing subsidiary threads */
//#define SI_ASYNCNL  -60     /* sent by glibc async name lookup completion */
//
//#define SI_FROMUSER(siptr)  ((siptr)->si_code <= 0)
//#define SI_FROMKERNEL(siptr)    ((siptr)->si_code > 0)

pub fn kill(tid: Tid, sig: usize) -> usize {
    info!("kill tid {} sig {}", tid, sig);
    assert!(tid > 0);
    let info = prepare_kill_siginfo(sig, tid);
    kill_proc_info(sig, info, tid).unwrap();
    0
}

pub fn prepare_kill_siginfo(sig: usize, tid: Tid) -> SigInfo {
    SigInfo {
        signo: sig as i32,
        errno: 0,
        code: SI_USER as i32,
        tid: tid,
    }
}

fn kill_proc_info(sig: usize, info: SigInfo, tid: Tid) -> LinuxResult {
    assert!(tid > 0);
    if sig != 0 {
        do_send_sig_info(sig, info, tid)
    } else {
        Ok(())
    }
}

fn do_send_sig_info(sig: usize, info: SigInfo, tid: Tid) -> LinuxResult {
    let task = task::get_task(tid).unwrap();
    let mut pending = task.sigpending.lock();
    pending.list.push(info);
    sigaddset(&mut pending.signal, sig);
    Ok(())
}

#[inline]
fn sigmask(sig: usize) -> usize {
    1 << (sig - 1)
}

#[inline]
fn sigaddset(set: &mut usize, sig: usize) {
    *set |= 1 << (sig - 1);
}

#[inline]
fn sigdelsetmask(set: &mut usize, mask: usize) {
    *set &= !mask;
}

pub fn rt_sigaction(sig: usize, act: usize, oact: usize, sigsetsize: usize) -> usize {
    assert_eq!(sigsetsize, 8);
    info!("rt_sigaction: sig {} act {:#X} oact {:#X}", sig, act, oact);
    assert!(act != 0);
    assert!(oact != 0);

    let task = task::current();

    if oact != 0 {
        let oact = oact as *mut SigAction;
        unsafe {
            *oact = task.sighand.lock().action[sig - 1];
        }
    }

    if act != 0 {
        let act = unsafe { &(*(act as *const SigAction)) };
        info!("act: {:#X} {:#X} {:#X}", act.handler, act.flags, act.mask);
        assert!((act.flags & SA_RESTART) != 0);
        assert!((act.flags & SA_RESTORER) == 0);

        let mut kact = act.clone();
        sigdelsetmask(&mut kact.mask, sigmask(SIGKILL) | sigmask(SIGSTOP));
        info!("get_signal signo {} handler {:#X}", sig, kact.handler);
        task.sighand.lock().action[sig - 1] = kact;
    }
    0
}

pub fn do_signal(tf: &mut TrapFrame) {
    if let Some(ksig) = get_signal() {
        /* Actually deliver the signal */
        handle_signal(&ksig, tf);
        return;
    }

    // Todo: handle 'regs->cause == EXC_SYSCALL';
}

fn get_signal() -> Option<KSignal> {
    let task = task::current();
    let _info = task.sigpending.lock().list.pop()?;
    let signo = _info.signo as usize;

    let action = task.sighand.lock().action[signo - 1];
    assert!(action.handler != 0);
    info!("get_signal signo {} handler {:#X}", signo, action.handler);
    Some(KSignal {action, _info, signo})
}

fn handle_signal(ksig: &KSignal, tf: &mut TrapFrame) {
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

fn get_sigframe(tf: &TrapFrame) -> usize {
    let sp = tf.regs.sp - SIGFRAME_SIZE;
    /* Align the stack frame. */
    align_down(sp, 16)
}

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

fn restore_sigcontext(tf: &mut TrapFrame, frame: &RTSigFrame) {
    *tf = frame.uc.mcontext.clone();
    // Todo: Restore the floating-point state. */
}

fn setup_sigcontext(frame: &mut RTSigFrame, tf: &TrapFrame) {
    frame.uc.mcontext = tf.clone();
    // Todo: Save the floating-point state.
}
