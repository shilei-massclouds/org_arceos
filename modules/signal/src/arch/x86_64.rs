use axhal::arch::TrapFrame;
use crate::KSignal;

pub fn rt_sigreturn() -> usize {
    unimplemented!("impl rt_sigreturn");
}

pub fn handle_signal(_ksig: &KSignal, _tf: &mut TrapFrame) {
    unimplemented!("impl handle_signal");
}
