#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::mem;

use axerrno::{LinuxError, LinuxResult};
use task::{current, Tid, TaskRef, TaskStruct};
use taskctx::SchedInfo;
use taskctx::THREAD_SIZE;
use taskctx::TaskStack;
use axhal::arch::gp_in_global;
use axhal::arch::{SR_SPP, SR_SPIE};
use memory_addr::align_up_4k;

bitflags::bitflags! {
    /// clone flags
    #[derive(Debug, Copy, Clone)]
    pub struct CloneFlags: usize {
        /// signal mask to be sent at exit
        const CSIGNAL       = 0x000000ff;
        /// set if VM shared between processes
        const CLONE_VM      = 0x00000100;
        /// set if fs info shared between processes
        const CLONE_FS      = 0x00000200;
        /// set if open files shared between processes
        const CLONE_FILES   = 0x00000400;
        /// set if signal handlers and blocked signals shared
        const CLONE_SIGHAND = 0x00000800;
        /// set if the parent wants the child to wake it up on mm_release
        const CLONE_VFORK   = 0x00004000;
        /// set if the tracing process can't force CLONE_PTRACE on this clone
        const CLONE_UNTRACED= 0x00800000;
    }
}

struct KernelCloneArgs {
    flags: CloneFlags,
    _name: String,
    _exit_signal: u32,
    stack: Option<usize>,
    entry: Option<*mut dyn FnOnce()>,
}

impl KernelCloneArgs {
    fn new(
        flags: CloneFlags,
        name: &str,
        exit_signal: u32,
        stack: Option<usize>,
        entry: Option<*mut dyn FnOnce()>,
    ) -> Self {
        Self {
            flags,
            _name: String::from(name),
            stack,
            _exit_signal: exit_signal,
            entry,
        }
    }

    /// The main fork-routine, as kernel_clone in linux kernel.
    ///
    /// It copies the process, and if successful kick-starts it and
    /// waits for it to finish using the VM if required.
    /// The arg *exit_signal* is expected to be checked for sanity
    /// by the caller.
    fn perform(&self) -> LinuxResult<Tid> {
        // Todo: handle ptrace in future.
        let trace = !self.flags.contains(CloneFlags::CLONE_UNTRACED);

        let task = self.copy_process(None, trace)?;
        debug!(
            "sched task fork: tid[{}] -> tid[{}].",
            task::current().tid(),
            task.tid()
        );

        let tid = task.tid();
        self.wake_up_new_task(task.clone());

        if self.flags.contains(CloneFlags::CLONE_VFORK) {
            task.wait_for_vfork_done();
        }

        Ok(tid)
    }

    /// Wake up a newly created task for the first time.
    ///
    /// This function will do some initial scheduler statistics housekeeping
    /// that must be done for every newly created context, then puts the task
    /// on the runqueue and wakes it.
    fn wake_up_new_task(&self, task: TaskRef) {
        let rq = run_queue::task_rq(&task.sched_info);
        rq.lock().activate_task(task.sched_info.clone());
        info!("wakeup the new task[{}].", task.tid());
    }

    fn copy_process(&self, mut tid: Option<Tid>, _trace: bool) -> LinuxResult<TaskRef> {
        info!("copy_process...");
        //assert!(!trace);
        if tid.is_none() {
            tid = Some(task::alloc_tid());
        }

        let mut task = current().dup_task_struct();
        //copy_files();
        self.copy_fs(&mut task)?;
        //copy_sighand();
        //copy_signal();
        self.copy_mm(&mut task)?;
        self.copy_thread(&mut task, tid.unwrap())?;

        if self.flags.contains(CloneFlags::CLONE_VFORK) {
            task.init_vfork_done();
        }

        let arc_task = Arc::new(task);
        task::register_task(arc_task.clone());
        info!("copy_process tid: {} -> {}", current().tid(), arc_task.tid());
        Ok(arc_task)
    }

    fn copy_mm(&self, task: &mut TaskStruct) -> LinuxResult {
        if self.flags.contains(CloneFlags::CLONE_VM) {
            task.mm = current().mm.clone();
        } else {
            panic!("NO CLONE_VM!");
            //let mm = current().mm().lock().dup();
            //task.mm = Some(Arc::new(SpinNoIrq::new(mm)));
        }
        Ok(())
    }

    fn copy_fs(&self, task: &mut TaskStruct) -> LinuxResult {
        if self.flags.contains(CloneFlags::CLONE_FS) {
            /* task.fs is already what we want */
            let fs = task::current().fs.clone();
            let mut locked_fs = fs.lock();
            if locked_fs.in_exec {
                return Err(LinuxError::EAGAIN);
            }
            locked_fs.users += 1;
            return Ok(());
        }
        task.fs.lock().copy_fs_struct(task::current().fs.clone());
        Ok(())
    }

    fn copy_thread(&self, task: &mut TaskStruct, tid: Tid) -> LinuxResult {
        info!("copy_thread ...");

        let mut sched_info = SchedInfo::new();
        //sched_info.init(self.entry, task_entry as usize, 0.into());
        /////////////////////
        sched_info.entry = self.entry;
        sched_info.kstack = Some(TaskStack::alloc(align_up_4k(THREAD_SIZE)));
        /////////////////////
        sched_info.init_tid(tid);
        sched_info.init_tgid(tid);
        if let Some(mm) = task.try_mm() {
            let locked_mm = mm.lock();
            sched_info.set_mm(locked_mm.id(), locked_mm.pgd());
        }

        let pt_regs = sched_info.pt_regs();
        if self.entry.is_some() {
            *pt_regs = unsafe { mem::zeroed() };
            pt_regs.regs.gp = gp_in_global();
            // Supervisor/Machine, irqs on:
            pt_regs.sstatus = SR_SPP | SR_SPIE;
        } else {
            let ctx = taskctx::current_ctx();
            *pt_regs = ctx.pt_regs().clone();
            if let Some(sp) = self.stack {
                pt_regs.regs.sp = sp; // User fork
            }
            /*
            if (self.flags.contains(CLONE_SETTLS))
                pt_regs.regs.tp = tls;
                */
            pt_regs.regs.a0 = 0; // Return value of fork()
        }

        let sp = sched_info.pt_regs_addr();
        sched_info.thread.get_mut().init(task_entry as usize, sp.into(), 0.into());
        task.sched_info = Arc::new(sched_info);

        info!("copy_thread!");
        Ok(())
    }
}

// Todo: We should move task_entry to taskctx.
// Now schedule_tail: 'run_queue::force_unlock();` hinders us.
// Consider to move it to sched first!
extern "C" fn task_entry() -> ! {
    info!("################ task_entry ...");
    // schedule_tail
    // unlock runqueue for freshly created task
    run_queue::force_unlock();

    let task = crate::current();
    if let Some(entry) = task.sched_info.entry {
        unsafe { Box::from_raw(entry)() };
    }

    let sp = task::current().pt_regs_addr();
    axhal::arch::ret_from_fork(sp);
    unimplemented!("task_entry!");
}

/// Create a user mode thread.
///
/// Invoke `f` to do some preparations before entering userland.
pub fn user_mode_thread<F>(f: F, flags: CloneFlags) -> Tid
where
    F: FnOnce() + 'static,
{
    info!("create a user mode thread ...");
    assert_eq!(flags.intersection(CloneFlags::CSIGNAL).bits(), 0);
    //assert!((flags.bits() & CloneFlags::CSIGNAL.bits()) == 0);
    let f = Box::into_raw(Box::new(f));
    let args = KernelCloneArgs::new(
        flags | CloneFlags::CLONE_VM | CloneFlags::CLONE_UNTRACED,
        "",
        0,
        None,
        Some(f),
    );
    args.perform().expect("kernel_clone failed.")
}

///
/// Clone thread according to SysCall requirements
///
pub fn sys_clone(
    flags: usize, stack: usize, tls: usize, ptid: usize, ctid: usize
) -> usize {
    assert_eq!(tls, 0);
    assert_eq!(ptid, 0);
    assert_eq!(ctid, 0);

    let flags = CloneFlags::from_bits_truncate(flags);
    let exit_signal = flags.intersection(CloneFlags::CSIGNAL).bits() as u32;
    let flags = flags.difference(CloneFlags::CSIGNAL);
    let stack = if stack == 0 {
        None
    } else {
        Some(stack)
    };
    let args = KernelCloneArgs::new(flags, "", exit_signal, stack, None);
    warn!("impl clone: flags {:#X} sig {:#X} stack {:#X} ptid {:#X} tls {:#X} ctid {:#X}",
                   flags.bits(), exit_signal,
                   stack.unwrap_or(0), ptid, tls, ctid);
    args.perform().unwrap_or(usize::MAX)
}
