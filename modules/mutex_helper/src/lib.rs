#![no_std]

extern crate alloc;
use alloc::sync::Arc;

use task::{TaskRef, current};
use waitqueue::Waiter;

#[macro_export]
macro_rules! mutex_lock {
    ($arg:tt) => {
        $arg.lock(mutex_helper::MutexHelper::new())
    }
}

pub struct MutexHelper {
    task: TaskRef,
}

impl MutexHelper {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            task: current().as_task_ref().clone(),
        })
    }
}

impl Waiter for MutexHelper {
    fn wid(&self) -> u64 {
        self.task.get_task_pid() as u64
    }

    fn block(&self) {
        let rq = run_queue::task_rq(&self.task);
        rq.lock().resched(false);
    }

    fn unblock(&self, resched: bool) {
        let rq = run_queue::task_rq(&self.task);
        rq.lock().add_task(self.task.clone());
        if resched {
            self.task.set_preempt_pending(true);
        }
    }

    fn on_waked(&self) {
        unimplemented!("");
    }
}
