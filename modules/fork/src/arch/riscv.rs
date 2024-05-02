use core::mem;
use alloc::sync::Arc;

use axhal::arch::gp_in_global;
use axhal::arch::{SR_SPP, SR_SPIE};
use task::{Tid, TaskStruct};
use axtype::align_up_4k;
use axerrno::LinuxResult;
use taskctx::SchedInfo;
use taskctx::THREAD_SIZE;
use taskctx::TaskStack;
use crate::CloneFlags;

pub fn copy_thread(
    task: &mut TaskStruct,
    entry: Option<*mut dyn FnOnce()>,
    stack: Option<usize>,
    tls: usize,
    flags: CloneFlags,
    tid: Tid
) -> LinuxResult {
    info!("copy_thread ...");

    let mut sched_info = SchedInfo::new();
    //sched_info.init(self.entry, task_entry as usize, 0.into());
    /////////////////////
    sched_info.entry = entry;
    sched_info.kstack = Some(TaskStack::alloc(align_up_4k(THREAD_SIZE)));
    /////////////////////
    sched_info.init_tid(tid);
    sched_info.init_tgid(tid);
    if let Some(mm) = task.try_mm() {
        let locked_mm = mm.lock();
        sched_info.set_mm(locked_mm.id(), locked_mm.pgd());
    }

    let pt_regs = sched_info.pt_regs();
    if entry.is_some() {
        *pt_regs = unsafe { mem::zeroed() };
        pt_regs.regs.gp = gp_in_global();
        // Supervisor/Machine, irqs on:
        pt_regs.sstatus = SR_SPP | SR_SPIE;
    } else {
        let ctx = taskctx::current_ctx();
        *pt_regs = ctx.pt_regs().clone();
        if let Some(sp) = stack {
            pt_regs.regs.sp = sp; // User fork
        }
        if flags.contains(CloneFlags::CLONE_SETTLS) {
            pt_regs.regs.tp = tls;
        }
        pt_regs.regs.a0 = 0; // Return value of fork()
    }

    let sp = sched_info.pt_regs_addr();
    sched_info.thread.get_mut().init(crate::task_entry as usize, sp.into(), 0.into());
    task.sched_info = Arc::new(sched_info);

    info!("copy_thread!");
    Ok(())
}
