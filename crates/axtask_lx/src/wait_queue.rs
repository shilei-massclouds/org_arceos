//! An Alternative WaitQueue
//! It's based on Linux Kernel `swait`.

use core::sync::atomic::AtomicI32;

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
        unimplemented!("wait() ..");
    }

    /// Blocks the current task and put it into the wait queue, until the given
    /// `condition` becomes true.
    ///
    /// Note that even other tasks notify this task, it will not wake up until
    /// the condition becomes true.
    pub fn wait_until<F>(&self, _condition: F)
    where
        F: Fn() -> bool,
    {
        unimplemented!("wait_until ..");
        /*
        let curr = crate::current();
        loop {
            let mut rq = current_run_queue::<NoPreemptIrqSave>();
            let wq = self.queue.lock();
            if condition() {
                break;
            }
            rq.blocked_resched(wq);
            // Preemption may occur here.
        }
        self.cancel_events(curr, false);
        */
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
    pub fn wait_timeout_until<F>(&self, dur: core::time::Duration, _condition: F) -> bool
    where
        F: Fn() -> bool,
    {
        unimplemented!("wait_timeout_until dur: {:?} ..", dur);
        /*
        let curr = crate::current();
        let deadline = axhal::time::wall_time() + dur;
        debug!(
            "task wait_timeout: {}, deadline={:?}",
            curr.id_name(),
            deadline
        );
        crate::timers::set_alarm_wakeup(deadline, curr.clone());

        let mut timeout = true;
        loop {
            let mut rq = current_run_queue::<NoPreemptIrqSave>();
            if axhal::time::wall_time() >= deadline {
                break;
            }
            let wq = self.queue.lock();
            if condition() {
                timeout = false;
                break;
            }

            rq.blocked_resched(wq);
            // Preemption may occur here.
        }
        // Always try to remove the task from the timer list.
        self.cancel_events(curr, true);
        timeout
        */
    }

    /// Wakes all tasks in the wait queue.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_all(&self, resched: bool) {
        unimplemented!("notify_all <- swake_up_all resched{resched}");
        /*
        while self.notify_one(resched) {
            // loop until the wait queue is empty
        }
        */
    }

    /// Wakes up one task in the wait queue, usually the first one.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_one(&self, resched: bool) -> bool {
        unsafe {
            swake_up_one(self);
            if resched {
                set_current_need_resched();
            }
        }
        true
    }
}

unsafe extern "C" {
    fn swake_up_one(wq: *const WaitQueue);
    fn set_current_need_resched();
}

/*
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use kernel_guard::{NoOp, NoPreemptIrqSave};
use kspin::{SpinNoIrq, SpinNoIrqGuard};

use crate::{AxTaskRef, CurrentTask, current_run_queue, select_run_queue};

pub struct WaitQueue {
    queue: SpinNoIrq<VecDeque<AxTaskRef>>,
}

pub(crate) type WaitQueueGuard<'a> = SpinNoIrqGuard<'a, VecDeque<AxTaskRef>>;

impl WaitQueue {

    /// Creates an empty wait queue with space for at least `capacity` elements.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: SpinNoIrq::new(VecDeque::with_capacity(capacity)),
        }
    }

    /// Cancel events by removing the task from the wait queue.
    /// If `from_timer_list` is true, try to remove the task from the timer list.
    fn cancel_events(&self, curr: CurrentTask, _from_timer_list: bool) {
        // A task can be wake up only one events (timer or `notify()`), remove
        // the event from another queue.
        if curr.in_wait_queue() {
            // wake up by timer (timeout).
            self.queue.lock().retain(|t| !curr.ptr_eq(t));
            curr.set_in_wait_queue(false);
        }

        // Try to cancel a timer event from timer lists.
        // Just mark task's current timer ticket ID as expired.
        #[cfg(feature = "irq")]
        if _from_timer_list {
            curr.timer_ticket_expired();
            // Note:
            //  this task is still not removed from timer list of target CPU,
            //  which may cause some redundant timer events because it still needs to
            //  go through the process of expiring an event from the timer list and invoking the callback.
            //  (it can be considered a lazy-removal strategy, it will be ignored when it is about to take effect.)
        }
    }


    /// Wake up the given task in the wait queue.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_task(&mut self, resched: bool, task: &AxTaskRef) -> bool {
        let mut wq = self.queue.lock();
        if let Some(index) = wq.iter().position(|t| Arc::ptr_eq(t, task)) {
            unblock_one_task(wq.remove(index).unwrap(), resched);
            true
        } else {
            false
        }
    }

    /// Transfers up to `count` tasks from this wait queue to another wait queue.
    ///
    /// Note: If the current wait queue contains fewer than `count` tasks, all available tasks will be moved.
    ///
    /// ## Arguments
    /// * `count` - The maximum number of tasks to be moved.
    /// * `target` - The target wait queue to which tasks will be moved.
    ///
    /// ## Returns
    /// The number of tasks actually requeued.  
    pub fn requeue(&self, mut count: usize, target: &WaitQueue) -> usize {
        let tasks: Vec<_> = {
            let mut wq = self.queue.lock();
            count = count.min(wq.len());
            wq.drain(..count).collect()
        };
        if !tasks.is_empty() {
            let mut wq = target.queue.lock();
            wq.extend(tasks);
        }
        count
    }

    /// Returns the number of tasks in the wait queue.
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Returns true if the wait queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }
}

fn unblock_one_task(task: AxTaskRef, resched: bool) {
    // Mark task as not in wait queue.
    task.set_in_wait_queue(false);
    // Select run queue by the CPU set of the task.
    // Use `NoOp` kernel guard here because the function is called with holding the
    // lock of wait queue, where the irq and preemption are disabled.
    select_run_queue::<NoOp>(&task).unblock_task(task, resched)
}
*/
