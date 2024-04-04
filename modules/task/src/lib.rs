#![no_std]
#![feature(get_mut_unchecked)]

use core::ops::Deref;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{alloc::Layout, cell::UnsafeCell, ptr::NonNull};

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;

use axhal::arch::TaskContext as ThreadStruct;
use mm::MmStruct;
use mm::switch_mm;
use spinlock::SpinNoIrq;
use fstree::FsStruct;
use filetable::FileTable;
use memory_addr::{align_down, PAGE_SIZE_4K};
use axhal::trap::{TRAPFRAME_SIZE, STACK_ALIGN};

pub const THREAD_SIZE: usize = 32 * PAGE_SIZE_4K;

pub type Pid = usize;

static NEXT_PID: AtomicUsize = AtomicUsize::new(0);

pub struct TaskStack {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl TaskStack {
    pub fn alloc(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 16).unwrap();
        Self {
            ptr: NonNull::new(unsafe { alloc::alloc::alloc(layout) }).unwrap(),
            layout,
        }
    }

    pub const fn top(&self) -> usize {
        unsafe { core::mem::transmute(self.ptr.as_ptr().add(self.layout.size())) }
    }
}

impl Drop for TaskStack {
    fn drop(&mut self) {
        unsafe { alloc::alloc::dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

pub struct TaskStruct {
    pid:    Pid,
    tgid:   Pid,

    pub entry: Option<*mut dyn FnOnce()>,

    mm: Option<Arc<SpinNoIrq<MmStruct>>>,
    pub active_mm_id: AtomicUsize,
    pub fs: Arc<SpinNoIrq<FsStruct>>,
    pub filetable: Arc<SpinNoIrq<FileTable>>,

    pub kstack: Option<TaskStack>,
    /* CPU-specific state of this task: */
    pub thread: UnsafeCell<ThreadStruct>,
}

unsafe impl Send for TaskStruct {}
unsafe impl Sync for TaskStruct {}

impl TaskStruct {
    pub fn new() -> Self {
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        error!("pid {}", pid);
        Self {
            pid: pid,
            tgid: pid,

            entry: None,

            mm: None,
            active_mm_id: AtomicUsize::new(0),
            fs: Arc::new(SpinNoIrq::new(FsStruct::new())),
            filetable: Arc::new(SpinNoIrq::new(FileTable::new())),

            kstack: None,
            thread: UnsafeCell::new(ThreadStruct::new()),
        }
    }

    pub fn pid(&self) -> usize {
        self.pid
    }

    pub fn tgid(&self) -> usize {
        self.tgid
    }

    pub fn pt_regs(&self) -> usize {
        self.kstack.as_ref().unwrap().top() - align_down(TRAPFRAME_SIZE, STACK_ALIGN)
    }

    pub fn try_mm(&self) -> Option<Arc<SpinNoIrq<MmStruct>>> {
        self.mm.as_ref().and_then(|mm| Some(mm.clone()))
    }

    pub fn mm(&self) -> Arc<SpinNoIrq<MmStruct>> {
        self.mm.as_ref().expect("NOT a user process.").clone()
    }

    pub fn alloc_mm(&mut self) {
        error!("alloc_mm...");
        assert!(self.mm.is_none());
        self.mm.replace(Arc::new(SpinNoIrq::new(MmStruct::new())));
        switch_mm(0, self.mm());
    }

    pub fn dup_task_struct(&self) -> Arc<Self> {
        debug!("dup_task_struct ...");
        let mut tsk = Self::new();
        tsk.fs = self.fs.clone();
        Arc::new(tsk)
    }

    pub fn get_task_pid(&self) -> Pid {
        self.pid
    }

    #[inline]
    pub const unsafe fn ctx_mut_ptr(&self) -> *mut ThreadStruct {
        self.thread.get()
    }
}

/// The reference type of a task.
pub type TaskRef = Arc<TaskStruct>;

/// A wrapper of [`TaskRef`] as the current task.
pub struct CurrentTask(ManuallyDrop<TaskRef>);

impl CurrentTask {
    pub(crate) fn try_get() -> Option<Self> {
        let ptr: *const TaskStruct = axhal::cpu::current_task_ptr();
        if !ptr.is_null() {
            Some(Self(unsafe { ManuallyDrop::new(TaskRef::from_raw(ptr)) }))
        } else {
            None
        }
    }

    pub(crate) fn get() -> Self {
        Self::try_get().expect("current task is uninitialized")
    }

    pub fn ptr_eq(&self, other: &TaskRef) -> bool {
        Arc::ptr_eq(&self, other)
    }

    /// Converts [`CurrentTask`] to [`TaskRef`].
    pub fn as_task_ref(&self) -> &TaskRef {
        &self.0
    }

    pub fn as_task_mut(&mut self) -> &mut TaskStruct {
        unsafe {
            Arc::get_mut_unchecked(&mut self.0)
        }
    }

    pub(crate) unsafe fn init_current(init_task: TaskRef) {
        error!("CurrentTask::init_current...");
        let ptr = Arc::into_raw(init_task);
        axhal::cpu::set_current_task_ptr(ptr);
    }

    pub unsafe fn set_current(prev: Self, next: TaskRef) {
        error!("CurrentTask::set_current...");
        let Self(arc) = prev;
        ManuallyDrop::into_inner(arc); // `call Arc::drop()` to decrease prev task reference count.
        let ptr = Arc::into_raw(next);
        axhal::cpu::set_current_task_ptr(ptr);
    }
}

impl Deref for CurrentTask {
    type Target = TaskRef;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Gets the current task.
///
/// # Panics
///
/// Panics if the current task is not initialized.
pub fn current() -> CurrentTask {
    CurrentTask::get()
}

/// Current task gives up the CPU time voluntarily, and switches to another
/// ready task.
pub fn yield_now() {
    unimplemented!("yield_now");
}

/// Exits the current task.
pub fn exit(exit_code: i32) -> ! {
    unimplemented!("exit {}", exit_code);
}

pub fn init() {
    error!("task::start ...");
    let init_task = Arc::new(TaskStruct::new());
    //init_task.set_state(TaskState::Running);
    unsafe { CurrentTask::init_current(init_task) }
}
