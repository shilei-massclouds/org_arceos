#![no_std]

extern crate alloc;
use alloc::sync::Arc;

use task::{TaskRef, current};
use waitqueue::Waiter;

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
        unimplemented!("");
    }

    fn unblock(&self, _resched: bool) {
        unimplemented!("");
    }

    fn on_waked(&self) {
        unimplemented!("");
    }
}
