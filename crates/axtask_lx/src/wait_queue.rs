//! An Alternative WaitQueue
//! It's based on Linux Kernel `swait`.

use core::ffi::{c_void, c_int};
use core::sync::atomic::AtomicI32;
use alloc::boxed::Box;

type ConditionFn = unsafe extern "C" fn(opaque: *mut c_void) -> c_int;

unsafe extern "C" fn condition_fn_hook<F>(
    opaque: *mut c_void
) -> c_int
where
    F: FnOnce() -> bool,
{
    let boxed_closure = Box::from_raw(opaque as *mut F);
    if (*boxed_closure)() {
        1
    } else {
        0
    }
}

fn get_condition_fn<F>() -> ConditionFn
where
    F: FnOnce() -> bool,
{
    condition_fn_hook::<F>
}

/// An equivalence of list_head in Linux Kernel.
/// FixMe: wrap it as a standalone crate.
#[repr(C)]
pub struct LinuxList {
    _next: *const LinuxList,
    _prev: *const LinuxList,
}

impl LinuxList {
    const fn new() -> Self {
        Self {
            _next: core::ptr::null(),
            _prev: core::ptr::null(),
        }
    }

    fn is_inited(&self) -> bool {
        assert!(self._next.is_null() == self._prev.is_null());
        // Only need to check one of them
        !self._next.is_null()
    }
}

unsafe impl Sync for LinuxList {}

const ARCH_SPIN_LOCK_UNLOCKED: i32 = 0;
const SPINLOCK_MAGIC: u32 = 0xdead4ead;
const SPINLOCK_OWNER_INIT: usize = usize::MAX;

type ArchSpinLock = AtomicI32;

/// An equivalence of spinlock in Linux Kernel.
/// FixMe: it will be an alternative impl for spinlock.
/// Wrap it as a standalone crate.
#[repr(C)]
pub struct RawSpinLock {
    _raw_lock: ArchSpinLock,
    _magic: u32,
    _owner_cpu: u32,
    _owner: usize,  // opaque pointer
}

impl RawSpinLock {
    const fn new() -> Self {
        Self {
            _raw_lock: ArchSpinLock::new(ARCH_SPIN_LOCK_UNLOCKED),
            _magic: SPINLOCK_MAGIC,
            _owner_cpu: u32::MAX,
            _owner: SPINLOCK_OWNER_INIT,
        }
    }
}

/// A queue to store sleeping tasks.
///
/// # Examples
///
/// ```
/// use axtask::WaitQueue;
/// use core::sync::atomic::{AtomicU32, Ordering};
///
/// static VALUE: AtomicU32 = AtomicU32::new(0);
/// static WQ: WaitQueue = WaitQueue::new();
///
/// axtask::init_scheduler();
/// // spawn a new task that updates `VALUE` and notifies the main task
/// axtask::spawn(|| {
///     assert_eq!(VALUE.load(Ordering::Acquire), 0);
///     VALUE.fetch_add(1, Ordering::Release);
///     WQ.notify_one(true); // wake up the main task
/// });
///
/// WQ.wait(); // block until `notify()` is called
/// assert_eq!(VALUE.load(Ordering::Acquire), 1);
/// ```
///
/// FixMe: In fact, it should be named with `SWaitQueue`,
/// because it's based on `swait_queue_head` in Linux kernel.
///
#[repr(C)]
pub struct WaitQueue {
    _lock:       RawSpinLock,
    _task_list:  LinuxList,
}

impl WaitQueue {
    /// Creates an empty wait queue.
    pub const fn new() -> Self {
        Self {
            _lock: RawSpinLock::new(),
            _task_list: LinuxList::new(),
        }
    }

    /// Blocks the current task and put it into the wait queue, until other task
    /// notifies it.
    pub fn wait(&self) {
        self.check_or_init();
        unsafe {
            swait_uninterruptible(self);
        }
    }

    /// Blocks the current task and put it into the wait queue, until the given
    /// `condition` becomes true.
    ///
    /// Note that even other tasks notify this task, it will not wake up until
    /// the condition becomes true.
    pub fn wait_until<F>(&self, condition: F)
    where
        F: Fn() -> bool,
    {
        self.check_or_init();

        let opaque = Box::into_raw(Box::new(condition)) as *mut c_void;
        let condition_fn = get_condition_fn::<F>();
        unsafe {
            swait_until(self, condition_fn, opaque);
        }
    }

    /// Blocks the current task and put it into the wait queue, until other tasks
    /// notify it, or the given duration has elapsed.
    #[cfg(feature = "irq")]
    pub fn wait_timeout(&self, dur: core::time::Duration) -> bool {
        unimplemented!("wait_timeout dur: {:?} ..", dur);
        /*
        let mut rq = current_run_queue::<NoPreemptIrqSave>();
        let curr = crate::current();
        let deadline = axhal::time::wall_time() + dur;
        debug!(
            "task wait_timeout: {} deadline={:?}",
            curr.id_name(),
            deadline
        );
        crate::timers::set_alarm_wakeup(deadline, curr.clone());

        rq.blocked_resched(self.queue.lock());

        let timeout = curr.in_wait_queue(); // still in the wait queue, must have timed out

        // Always try to remove the task from the timer list.
        self.cancel_events(curr, true);
        timeout
        */
    }

    /// Blocks the current task and put it into the wait queue, until the given
    /// `condition` becomes true, or the given duration has elapsed.
    ///
    /// Note that even other tasks notify this task, it will not wake up until
    /// the above conditions are met.
    #[cfg(feature = "irq")]
    pub fn wait_timeout_until<F>(&self, dur: core::time::Duration, condition: F) -> bool
    where
        F: Fn() -> bool,
    {
        self.check_or_init();

        let opaque = Box::into_raw(Box::new(condition)) as *mut c_void;
        let condition_fn = get_condition_fn::<F>();
        let timeout = unsafe {
            swait_timeout_until(self, dur.as_millis() as i64, condition_fn, opaque)
        };
        /*
         * swait_timeout_until
         *
         * - returns remaining jiffies when conditions are met
         *   or 0 whick means timeout.
         *
         * So just check 'timeout == 0'.
         */
        timeout == 0
    }

    /// Wakes all tasks in the wait queue.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_all(&self, resched: bool) {
        self.check_or_init();
        unsafe {
            swake_up_all(self);
            if resched {
                set_current_need_resched();
            }
        }
    }

    /// Wakes up one task in the wait queue, usually the first one.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_one(&self, resched: bool) -> bool {
        self.check_or_init();
        unsafe {
            swake_up_one(self);
            if resched {
                set_current_need_resched();
            }
        }
        true
    }

    /// Returns the number of tasks in the wait queue.
    pub fn len(&self) -> usize {
        self.check_or_init();
        unsafe {
            return swait_count_sleepers(self) as usize;
        }
    }

    /// Returns true if the wait queue is empty.
    pub fn is_empty(&self) -> bool {
        self.check_or_init();
        self.len() == 0
    }

    /// Check or perform a self-initialization.
    fn check_or_init(&self) {
        if self._task_list.is_inited() {
            return;
        }

        unsafe {
            swait_check_or_init(self);
        }
    }
}

unsafe extern "C" {
    fn set_current_need_resched();
    fn swake_up_one(wq: *const WaitQueue);
    fn swake_up_all(wq: *const WaitQueue);

    fn swait_timeout_until(
        wq: *const WaitQueue,
        timeout: i64,
        condition: ConditionFn,
        opaque: *mut c_void
    ) -> c_int;

    fn swait_until(
        wq: *const WaitQueue,
        condition: ConditionFn,
        opaque: *mut c_void
    );

    fn swait_uninterruptible(wq: *const WaitQueue);
    fn swait_check_or_init(wq: *const WaitQueue);
    fn swait_count_sleepers(wq: *const WaitQueue) -> c_int;
}
