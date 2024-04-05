#![no_std]

use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

use task::current;
use mutex_base::Mutex;

pub trait MutexTrait<T: ?Sized> {
    fn lock(&self) -> MutexGuard<T>;
    fn try_lock(&self) -> Option<MutexGuard<T>>;
    fn force_unlock(&self);
}

/// A guard that provides mutable data access.
///
/// When the guard falls out of scope it will release the lock.
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    lock: &'a Mutex<T>,
    data: *mut T,
}

impl<T: ?Sized> MutexTrait<T> for Mutex<T> {
    /// Locks the [`Mutex`] and returns a guard that permits access to the inner data.
    ///
    /// The returned value may be dereferenced for data access
    /// and the lock will be dropped when the guard falls out of scope.
    fn lock(&self) -> MutexGuard<T> {
        let current_id = current().pid() as u64;
        loop {
            // Can fail to lock even if the spinlock is not locked. May be more efficient than `try_lock`
            // when called in a loop.
            match self.owner_id.compare_exchange_weak(
                0,
                current_id,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(owner_id) => {
                    assert_ne!(
                        owner_id,
                        current_id,
                        "{} tried to acquire mutex it already owns.",
                        current().pid()
                    );
                    // Wait until the lock looks unlocked before retrying
                    loop {
                        let curr = task::current();
                        let mut rq = run_queue::task_rq(curr.as_task_ref()).lock();
                        if !self.is_locked() {
                            break;
                        }
                        //curr.set_in_wait_queue(true);
                        //curr.set_state(TaskState::Blocked);
                        self.wq.push_back(curr.pid());
                        rq.resched(false);
                    }
                    //self.cancel_events(crate::current());
                }
            }
        }
        MutexGuard {
            lock: self,
            data: unsafe { &mut *self.data.get() },
        }
    }

    /// Try to lock this [`Mutex`], returning a lock guard if successful.
    #[inline(always)]
    fn try_lock(&self) -> Option<MutexGuard<T>> {
        let current_id = current().pid() as u64;
        // The reason for using a strong compare_exchange is explained here:
        // https://github.com/Amanieu/parking_lot/pull/207#issuecomment-575869107
        if self
            .owner_id
            .compare_exchange(0, current_id, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(MutexGuard {
                lock: self,
                data: unsafe { &mut *self.data.get() },
            })
        } else {
            None
        }
    }

    /// Force unlock the [`Mutex`].
    ///
    /// # Safety
    ///
    /// This is *extremely* unsafe if the lock is not held by the current
    /// thread. However, this can be useful in some instances for exposing
    /// the lock to FFI that doesn’t know how to deal with RAII.
    fn force_unlock(&self) {
        let owner_id = self.owner_id.swap(0, Ordering::Release);
        assert_eq!(
            owner_id,
            current().pid() as u64,
            "{} tried to release mutex it doesn't own",
            current().pid()
        );
        if let Some(tid) = self.wq.pop_front() {
            let task = tid_map::get_task(tid).unwrap();
            //task.set_in_wait_queue(false);
            let task2 = task.clone();
            let mut rq = run_queue::task_rq(&task2).lock();
            rq.add_task(task);
            /*
            if resched {
                #[cfg(feature = "preempt")]
                crate::current().set_preempt_pending(true);
            }
            */
        }
    }
}

impl<'a, T: ?Sized> Deref for MutexGuard<'a, T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        // We know statically that only we are referencing data
        unsafe { &*self.data }
    }
}

impl<'a, T: ?Sized> DerefMut for MutexGuard<'a, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        // We know statically that only we are referencing data
        unsafe { &mut *self.data }
    }
}

impl<'a, T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: ?Sized> Drop for MutexGuard<'a, T> {
    /// The dropping of the [`MutexGuard`] will release the lock it was created from.
    fn drop(&mut self) {
        unsafe { self.lock.force_unlock() }
    }
}
