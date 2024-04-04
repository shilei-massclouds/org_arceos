//! A naïve sleeping mutex.
#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;

use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

use waitqueue::{AxWaitQueue, WaiterRef};

/// A mutual exclusion primitive useful for protecting shared data, similar to
/// [`std::sync::Mutex`](https://doc.rust-lang.org/std/sync/struct.Mutex.html).
///
/// When the mutex is locked, the current task will block and be put into the
/// wait queue. When the mutex is unlocked, all tasks waiting on the queue
/// will be woken up.
pub struct AxMutex<T: ?Sized> {
    wq: AxWaitQueue,
    owner_id: AtomicU64,
    data: UnsafeCell<T>,
}

/// A guard that provides mutable data access.
///
/// When the guard falls out of scope it will release the lock.
pub struct AxMutexGuard<'a, T: ?Sized + 'a> {
    lock: &'a AxMutex<T>,
    data: *mut T,
}

// Same unsafe impls as `std::sync::AxMutex`
unsafe impl<T: ?Sized + Send> Sync for AxMutex<T> {}
unsafe impl<T: ?Sized + Send> Send for AxMutex<T> {}

impl<T> AxMutex<T> {
    /// Creates a new [`AxMutex`] wrapping the supplied data.
    #[inline(always)]
    pub const fn new(data: T) -> Self {
        Self {
            wq: AxWaitQueue::new(),
            owner_id: AtomicU64::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Consumes this [`AxMutex`] and unwraps the underlying data.
    #[inline(always)]
    pub fn into_inner(self) -> T {
        // We know statically that there are no outstanding references to
        // `self` so there's no need to lock.
        let AxMutex { data, .. } = self;
        data.into_inner()
    }
}

impl<T: ?Sized> AxMutex<T> {
    /// Returns `true` if the lock is currently held.
    ///
    /// # Safety
    ///
    /// This function provides no synchronization guarantees and so its result should be considered 'out of date'
    /// the instant it is called. Do not use it for synchronization purposes. However, it may be useful as a heuristic.
    #[inline(always)]
    pub fn is_locked(&self) -> bool {
        self.owner_id.load(Ordering::Relaxed) != 0
    }

    /// Locks the [`AxMutex`] and returns a guard that permits access to the inner data.
    ///
    /// The returned value may be dereferenced for data access
    /// and the lock will be dropped when the guard falls out of scope.
    pub fn lock(&self, current: WaiterRef) -> AxMutexGuard<T> {
        let current_id = current.wid();
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
                        current.wid()
                    );
                    // Wait until the lock looks unlocked before retrying
                    self.wq.wait_until(|| !self.is_locked(), current.clone());
                }
            }
        }
        AxMutexGuard {
            lock: self,
            data: unsafe { &mut *self.data.get() },
        }
    }

    /*
    /// Try to lock this [`AxMutex`], returning a lock guard if successful.
    #[inline(always)]
    pub fn try_lock(&self) -> Option<AxMutexGuard<T>> {
        let current_id = current().id().as_u64();
        // The reason for using a strong compare_exchange is explained here:
        // https://github.com/Amanieu/parking_lot/pull/207#issuecomment-575869107
        if self
            .owner_id
            .compare_exchange(0, current_id, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(AxMutexGuard {
                lock: self,
                data: unsafe { &mut *self.data.get() },
            })
        } else {
            None
        }
    }
    */

    /// Force unlock the [`AxMutex`].
    ///
    /// # Safety
    ///
    /// This is *extremely* unsafe if the lock is not held by the current
    /// thread. However, this can be useful in some instances for exposing
    /// the lock to FFI that doesn’t know how to deal with RAII.
    pub unsafe fn force_unlock(&self) {
        let owner_id = self.owner_id.swap(0, Ordering::Release);
        self.wq.notify_one(true);
    }

    /*
    /// Returns a mutable reference to the underlying data.
    ///
    /// Since this call borrows the [`AxMutex`] mutably, and a mutable reference is guaranteed to be exclusive in
    /// Rust, no actual locking needs to take place -- the mutable borrow statically guarantees no locks exist. As
    /// such, this is a 'zero-cost' operation.
    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut T {
        // We know statically that there are no other references to `self`, so
        // there's no need to lock the inner mutex.
        unsafe { &mut *self.data.get() }
    }
    */
}

/*
impl<T: ?Sized + Default> Default for AxMutex<T> {
    #[inline(always)]
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for AxMutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.try_lock() {
            Some(guard) => write!(f, "AxMutex {{ data: ")
                .and_then(|()| (*guard).fmt(f))
                .and_then(|()| write!(f, "}}")),
            None => write!(f, "AxMutex {{ <locked> }}"),
        }
    }
}
*/

impl<'a, T: ?Sized> Deref for AxMutexGuard<'a, T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        // We know statically that only we are referencing data
        unsafe { &*self.data }
    }
}

impl<'a, T: ?Sized> DerefMut for AxMutexGuard<'a, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        // We know statically that only we are referencing data
        unsafe { &mut *self.data }
    }
}

/*
impl<'a, T: ?Sized + fmt::Debug> fmt::Debug for AxMutexGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
*/

impl<'a, T: ?Sized> Drop for AxMutexGuard<'a, T> {
    /// The dropping of the [`AxMutexGuard`] will release the lock it was created from.
    fn drop(&mut self) {
        error!("============== AxMutexGuard drop...");
        unsafe { self.lock.force_unlock() }
    }
}

/*
#[cfg(test)]
mod tests {
    use crate::AxMutex;
    use axtask as thread;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn may_interrupt() {
        // simulate interrupts
        if rand::random::<u32>() % 3 == 0 {
            thread::yield_now();
        }
    }

    #[test]
    fn lots_and_lots() {
        INIT.call_once(thread::init_scheduler);

        const NUM_TASKS: u32 = 10;
        const NUM_ITERS: u32 = 10_000;
        static M: AxMutex<u32> = AxMutex::new(0);

        fn inc(delta: u32) {
            for _ in 0..NUM_ITERS {
                let mut val = M.lock();
                *val += delta;
                may_interrupt();
                drop(val);
                may_interrupt();
            }
        }

        for _ in 0..NUM_TASKS {
            thread::spawn(|| inc(1));
            thread::spawn(|| inc(2));
        }

        println!("spawn OK");
        loop {
            let val = M.lock();
            if *val == NUM_ITERS * NUM_TASKS * 3 {
                break;
            }
            may_interrupt();
            drop(val);
            may_interrupt();
        }

        assert_eq!(*M.lock(), NUM_ITERS * NUM_TASKS * 3);
        println!("AxMutex test OK");
    }
}
*/
