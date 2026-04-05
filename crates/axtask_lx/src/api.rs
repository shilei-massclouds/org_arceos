//! Task APIs for multi-task configuration.

use alloc::{string::String, sync::Arc, boxed::Box};
use alloc::ffi::CString;
use core::ptr;
use core::ffi::{c_void, c_int, c_long, c_char};
use core::sync::atomic::{AtomicU64, Ordering};
use axstage::{AxPlugin, AxStage};
use linux_adaptor::LinuxAdaptorState;
use linux_config::{CLONE_FS, CLONE_FILES};

const MAX_NICE: isize =  19;
const MIN_NICE: isize = -20;

/// The wrapper type for [`cpumask::CpuMask`] with SMP configuration.
pub type AxCpuMask = cpumask::CpuMask<{ axconfig::plat::MAX_CPU_NUM }>;

/*
use kernel_guard::NoPreemptIrqSave;

pub(crate) use crate::run_queue::{current_run_queue, select_run_queue};
*/

#[doc(cfg(feature = "multitask"))]
pub use crate::task::{CurrentTask, TaskId, TaskInner};
/*
#[doc(cfg(feature = "multitask"))]
pub use crate::task_ext::{TaskExtMut, TaskExtRef};
*/
#[doc(cfg(feature = "multitask"))]
pub use crate::wait_queue::WaitQueue;

/// The reference type of a task.
pub type AxTaskRef = Arc<crate::task::AxTask>;

type LinuxThreadFn = unsafe extern "C" fn(opaque: *mut c_void);

unsafe extern "C" fn thread_fn_hook<F>(opaque: *mut c_void)
where
    F: FnOnce(),
{
    let boxed_closure = Box::from_raw(opaque as *mut F);
    (*boxed_closure)();
    if current().id().as_u64() == 1 {
        // For main task(pid=1), shutdown the kernel.
        axhal::power::system_off();
    } else {
        exit(0);
    }
}

fn get_thread_fn<F>() -> LinuxThreadFn
where
    F: FnOnce(),
{
    thread_fn_hook::<F>
}

/*
cfg_if::cfg_if! {
    if #[cfg(feature = "sched-rr")] {
        const MAX_TIME_SLICE: usize = 5;
        pub(crate) type AxTask = axsched::RRTask<TaskInner, MAX_TIME_SLICE>;
        pub(crate) type Scheduler = axsched::RRScheduler<TaskInner, MAX_TIME_SLICE>;
    } else if #[cfg(feature = "sched-cfs")] {
        pub(crate) type AxTask = axsched::CFSTask<TaskInner>;
        pub(crate) type Scheduler = axsched::CFScheduler<TaskInner>;
    } else {
        // If no scheduler features are set, use FIFO as the default.
        pub(crate) type AxTask = axsched::FifoTask<TaskInner>;
        pub(crate) type Scheduler = axsched::FifoScheduler<TaskInner>;
    }
}

#[cfg(feature = "preempt")]
struct KernelGuardIfImpl;

#[cfg(feature = "preempt")]
#[crate_interface::impl_interface]
impl kernel_guard::KernelGuardIf for KernelGuardIfImpl {
    fn disable_preempt() {
        if let Some(curr) = current_may_uninit() {
            curr.disable_preempt();
        }
    }

    fn enable_preempt() {
        if let Some(curr) = current_may_uninit() {
            curr.enable_preempt(true);
        }
    }
}
*/

/// Gets the current task, or returns [`None`] if the current task is not
/// initialized.
pub fn current_may_uninit() -> Option<CurrentTask> {
    Some(CurrentTask)
}

/// Gets the current task.
///
/// # Panics
///
/// Panics if the current task is not initialized.
pub fn current() -> CurrentTask {
    CurrentTask
}

/// Initializes the task scheduler (for the primary CPU).
pub fn init_scheduler() {
    info!("Initialize scheduling...");

    // Initialize the cpu count information.
    //init_cpu_mask_full();

    // Initialize the run queue.
    //crate::run_queue::init();
    //#[cfg(feature = "irq")]
    //crate::timers::init();

    info!("  use linux scheduler.");
    linux_adaptor::advance_to(LinuxAdaptorState::InitSched);
}

/*
/// The full CPU mask of the system.
static CPU_MASK_FULL: lazyinit::LazyInit<AxCpuMask> = lazyinit::LazyInit::new();

/// Gets the cpu count information and initializes related data structures.
fn init_cpu_mask_full() {
    let cpu_num = axhal::cpu_num();
    let mut cpumask = AxCpuMask::new();
    for cpu_id in 0..cpu_num {
        cpumask.set(cpu_id, true);
    }

    CPU_MASK_FULL.call_once(|| cpumask);
}

pub(crate) fn cpu_mask_full() -> AxCpuMask {
    CPU_MASK_FULL
        .get()
        .expect("CPU mask not initialized")
        .clone()
}

/// Initializes the task scheduler for secondary CPUs.
pub fn init_scheduler_secondary() {
    crate::run_queue::init_secondary();
    #[cfg(feature = "irq")]
    crate::timers::init();
}
*/

/// Handles periodic timer ticks for the task manager.
///
/// For example, advance scheduler states, checks timed events, etc.
#[cfg(feature = "irq")]
#[doc(cfg(feature = "irq"))]
pub fn on_timer_tick() {
    /* FixMe: do timer in ArceOS. */
    debug!("MAYBE we need to implement on_timer_tick.");
    /*
    use kernel_guard::NoOp;
    crate::timers::check_events();
    // Since irq and preemption are both disabled here,
    // we can get current run queue with the default `kernel_guard::NoOp`.
    current_run_queue::<NoOp>().scheduler_timer_tick();
    */
}

/*
/// Adds the given task to the run queue, returns the task reference.
pub fn spawn_task(task: TaskInner) -> AxTaskRef {
    let task_ref = task.into_arc();
    select_run_queue::<NoPreemptIrqSave>(&task_ref).add_task(task_ref.clone());
    task_ref
}
*/

/// Spawns a new task with the given parameters.
///
/// Returns the task reference.
pub fn spawn_raw<F>(f: F, name: String, _stack_size: usize) -> AxTaskRef
where
    F: FnOnce() + Send + 'static,
{
    /* FixMe: handle _statck_size in linux. */
    let opaque = Box::into_raw(Box::new(f)) as *mut c_void;
    let thread_fn = get_thread_fn::<F>();
    let c_name = get_cname(&name);
    let pid = unsafe {
        kernel_thread(thread_fn, opaque, c_name.as_ptr(), 0)
    };
    crate::task::AxTask::new(pid)
}


/// Spawns a new task with the default parameters.
///
/// The default task name is an empty string. The default task stack size is
/// [`axconfig::TASK_STACK_SIZE`].
///
/// Returns the task reference.
pub fn spawn<F>(f: F) -> AxTaskRef
where
    F: FnOnce() + Send + 'static,
{
    spawn_raw(f, String::default(), axconfig::TASK_STACK_SIZE)
}

/// Create a user mode thread.
/// Compatible with Linux `user_mode_thread()`
fn ax_user_mode_thread<F>(f: F, flags: usize) -> AxTaskRef
where
    F: FnOnce() + Send + 'static,
{
    let opaque = Box::into_raw(Box::new(f)) as *mut c_void;
    let thread_fn = get_thread_fn::<F>();
    let pid = unsafe {
        user_mode_thread(thread_fn, opaque, flags)
    };
    crate::task::AxTask::new(pid)
}

/// Create a kernel thread.
/// Compatible with Linux `kernel_thread()`
fn ax_kernel_thread<F>(f: F, name: &str, flags: usize) -> AxTaskRef
where
    F: FnOnce() + Send + 'static,
{
    let opaque = Box::into_raw(Box::new(f)) as *mut c_void;
    let thread_fn = get_thread_fn::<F>();
    let c_name = get_cname(&name);
    let pid = unsafe {
        kernel_thread(thread_fn, opaque, c_name.as_ptr(), flags)
    };
    crate::task::AxTask::new(pid)
}

fn get_cname(name: &str) -> CString {
    assert!(name.len() < linux_config::TASK_COMM_LEN);
    CString::new(name).expect("bad task name")
}

/// Set the priority for current task.
///
/// The range of the priority is dependent on the underlying scheduler. For
/// example, in the [CFS] scheduler, the priority is the nice value, ranging from
/// -20 to 19.
///
/// Returns `true` if the priority is set successfully.
///
/// [CFS]: https://en.wikipedia.org/wiki/Completely_Fair_Scheduler
pub fn set_priority(nice: isize) -> bool {
    if nice < MIN_NICE || nice > MAX_NICE {
        return false;
    }

    let pid = current().id().as_u64() as i32;
    let ret = unsafe {
        linux_set_nice(pid, nice as c_long)
    };
    ret == 0
}

/// Set the affinity for the current task.
/// [`AxCpuMask`] is used to specify the CPU affinity.
/// Returns `true` if the affinity is set successfully.
///
/// TODO: support set the affinity for other tasks.
pub fn set_current_affinity(cpumask: AxCpuMask) -> bool {
    //error!("...");
    let mut i = 0;
    let mut mask: [u8; 8] = [0; 8];
    for byte in cpumask.as_bytes() {
        mask[i] = *byte;
        i += 1;
    }
    //error!("cpumask: {}", u64::from_le_bytes(mask));
    let pid = current().id().as_u64() as i32;
    unsafe {
        sched_setaffinity(pid, mask.as_ptr()) == 0
    }
}

/// Current task gives up the CPU time voluntarily, and switches to another
/// ready task.
pub fn yield_now() {
    unsafe {
        schedule();
    }
}

/// Current task is going to sleep for the given duration.
///
/// If the feature `irq` is not enabled, it uses busy-wait instead.
pub fn sleep(dur: core::time::Duration) {
    unimplemented!("sleep: {:?}", dur);
    //sleep_until(axhal::time::wall_time() + dur);
}

/// Current task is going to sleep, it will be woken up at the given deadline.
///
/// If the feature `irq` is not enabled, it uses busy-wait instead.
pub fn sleep_until(deadline: axhal::time::TimeValue) {
    let now = axhal::time::wall_time();
    if deadline <= now {
        return;
    }
    let timeout = deadline - now;

    #[cfg(feature = "irq")]
    unsafe {
        msleep(timeout.as_millis().try_into().unwrap());
    }
    #[cfg(not(feature = "irq"))]
    unimplemented!("mdelay");
}

/// Exits the current task.
pub fn exit(exit_code: i32) -> ! {
    unsafe {
        kthread_exit(exit_code);
    }
    unreachable!("exited!");
}

pub fn idle_loop(task_id: u64) {
    unsafe {
        linux_idle_loop(task_id as i32);
    }
}

unsafe extern "C" {
    fn msleep(msecs: usize);
    fn user_mode_thread(f: LinuxThreadFn, opaque: *mut c_void, flags: usize) -> i32;
    fn kernel_thread(f: LinuxThreadFn, opaque: *mut c_void, name: *const c_char, flags: usize) -> i32;
    fn linux_idle_loop(pid: i32);
    fn kthread_exit(exit_code: i32);
    fn schedule();
    fn linux_set_nice(pid: c_int, nice: c_long) -> c_int;
    fn sched_setaffinity(pid: c_int, mask: *const c_char) -> c_int;
    fn pin_task_on_cpu(pid: c_int, cpu_id: usize);
    fn cl_cpu_id() -> usize;
    fn set_kthreadd_task(pid: c_int);
    fn kthreadd(unused: *const c_void);
}

/*
/// The idle task routine.
///
/// It runs an infinite loop that keeps calling [`yield_now()`].
pub fn run_idle() -> ! {
    loop {
        yield_now();
        debug!("idle task: waiting for IRQs...");
        #[cfg(feature = "irq")]
        axhal::asm::wait_for_irqs();
    }
}
*/

axstage::register!("AxStartKInitdPre", AxStage::StartKInitdPre, |_, _| {
    linux_adaptor::advance_to(LinuxAdaptorState::StartSchedEarlier);
});

static IDLE_TASK_ID: AtomicU64 = AtomicU64::new(0);

// As Linux `kernel_init`
fn init_thread_fn(hartid: usize, dtb_pa: usize) {
    // InitSMPPre
    // InitSMP
    // SetupAllocLate
    // InitDriver
    // InitFS
    // BootAppPre
    // BootApp

    while axstage::advance(hartid, dtb_pa) {}
}

axstage::register!("AxInitSMPPre", AxStage::InitSMPPre, |_, _| {
    linux_adaptor::advance_to(LinuxAdaptorState::PrepareKernelInit);
});

axstage::register!("AxStartKInitd", AxStage::StartKInitd, |hartid, dtb_pa| {
    /*
     * We need to spawn init first so that it obtains pid 1, however
     * the init task will end up wanting to create kthreads, which, if
     * we schedule it before we create kthreadd, will OOPS.
     */
    let task = ax_user_mode_thread(move || {
        init_thread_fn(hartid, dtb_pa);
    }, CLONE_FS);
    unsafe {
        pin_task_on_cpu(task.id().as_u64() as i32, cl_cpu_id())
    }

    IDLE_TASK_ID.store(task.id().as_u64(), Ordering::Release);
});

axstage::register!("AxStartKThreadd", AxStage::StartKThreadd, |_, _| {
    let task = ax_kernel_thread(move || {
        unsafe { kthreadd(ptr::null()) };
    }, "", CLONE_FS | CLONE_FILES);

    unsafe {
        set_kthreadd_task(task.id().as_u64() as i32);
    }
});

axstage::register!("AxIdle", AxStage::EnterIdle, |_, _| {
    idle_loop(IDLE_TASK_ID.load(Ordering::Acquire));
});

pub fn system_exit() -> ! {
    exit(0);
}
